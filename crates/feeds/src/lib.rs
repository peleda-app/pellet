//! Remote lists for Pellet rules: download, parse into bounded fingerprint sets, cache, refresh.
//!
//! Every list a deployment enables is fetched on its own schedule from its `[http-list.*]`
//! definition and swapped into the rule set's remote lists, where `key_exists` sees it. The last
//! good copy of each list is cached as a fingerprint file, so a restart serves it at once and
//! only downloads again when it is due.

use std::{
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use flate2::read::GzDecoder;
use pellet_fetch::{Fetch, FetchError};
use pellet_rules::{Fingerprints, HttpList, ListFormat, RemoteLists};

const MAGIC: &[u8; 8] = b"PELLETF1";

/// Why a list could not be refreshed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FeedError {
    /// The download failed, timed out, or answered with an error status.
    #[error("download failed: {0}")]
    Download(String),
    /// The download or its decompressed content is larger than the list allows.
    #[error("larger than {0} bytes")]
    TooLarge(usize),
    /// The content is not gzip although the list says it is, or holds no keys.
    #[error("unusable content: {0}")]
    Content(String),
}

impl From<FetchError> for FeedError {
    fn from(error: FetchError) -> Self {
        match error {
            FetchError::Download(reason) => FeedError::Download(reason),
            FetchError::TooLarge(max) => FeedError::TooLarge(max),
        }
    }
}

/// Turns a downloaded body into fingerprints: gunzips when the list says so (never beyond
/// `max_size`), takes one key per line or the configured CSV field, skips blank lines, `#`
/// comments and keys longer than `max_entry_size`, and keeps at most `min(max_entries, cap)`.
pub fn parse(list: &HttpList, body: &[u8], cap: usize) -> Result<Fingerprints, FeedError> {
    let text = if list.gzipped {
        let mut decoded = Vec::new();
        GzDecoder::new(body)
            .take(list.max_size as u64 + 1)
            .read_to_end(&mut decoded)
            .map_err(|e| FeedError::Content(format!("gzip: {e}")))?;
        if decoded.len() > list.max_size {
            return Err(FeedError::TooLarge(list.max_size));
        }
        decoded
    } else {
        body.to_vec()
    };
    let text = String::from_utf8_lossy(&text);
    let limit = list.max_entries.min(cap);
    let mut lines = text.lines();
    if let ListFormat::Csv {
        skip_first: true, ..
    } = list.format
    {
        lines.next();
    }
    let keys: Vec<&str> = lines
        .filter_map(|line| match &list.format {
            ListFormat::Lines => Some(line.trim()),
            ListFormat::Csv { separator, key, .. } => line
                .split(*separator)
                .nth(*key)
                .map(|field| field.trim().trim_matches('"')),
        })
        .filter(|key| !key.is_empty() && !key.starts_with('#') && key.len() <= list.max_entry_size)
        .take(limit)
        .collect();
    if keys.is_empty() {
        return Err(FeedError::Content("no keys".into()));
    }
    Ok(Fingerprints::from_keys(keys))
}

/// The cache file of a list in `dir`.
pub fn cache_path(dir: &Path, list: &HttpList) -> PathBuf {
    dir.join(format!("{}.fp", list.name))
}

/// Writes a list's fingerprints atomically.
pub fn save(path: &Path, list: &Fingerprints) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(16 + list.len() * 8);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(list.len() as u64).to_le_bytes());
    for fingerprint in list.as_slice() {
        out.extend_from_slice(&fingerprint.to_le_bytes());
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, out)?;
    std::fs::rename(&tmp, path)
}

/// Reads a cached list and when it was written; `None` when missing or broken.
pub fn load(path: &Path) -> Option<(Fingerprints, SystemTime)> {
    let bytes = std::fs::read(path).ok()?;
    let written = std::fs::metadata(path).ok()?.modified().ok()?;
    if bytes.len() < 16 || &bytes[..8] != MAGIC {
        return None;
    }
    let count = u64::from_le_bytes(bytes[8..16].try_into().ok()?) as usize;
    if bytes.len() != 16 + count.checked_mul(8)? {
        return None;
    }
    let raw = bytes[16..]
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c))
        .collect();
    Some((Fingerprints::from_raw(raw), written))
}

/// Downloads, parses, publishes and caches one list; returns how many keys it holds.
pub async fn refresh(
    list: &HttpList,
    fetch: &dyn Fetch,
    remote: &RemoteLists,
    dir: &Path,
    cap: usize,
) -> Result<usize, FeedError> {
    let body = fetch.fetch(&list.url, list.timeout, list.max_size).await?;
    let fingerprints = parse(list, &body, cap)?;
    let len = fingerprints.len();
    if let Err(error) = save(&cache_path(dir, list), &fingerprints) {
        tracing::warn!(list = %list.name, %error, "caching the list failed");
    }
    remote.set(&list.name, fingerprints);
    Ok(len)
}

/// Publishes a list's cache if there is one, and tells how long until it is due again.
pub fn restore(list: &HttpList, remote: &RemoteLists, dir: &Path) -> Duration {
    match load(&cache_path(dir, list)) {
        Some((fingerprints, written)) => {
            remote.set(&list.name, fingerprints);
            let age = SystemTime::now()
                .duration_since(written)
                .unwrap_or_default();
            list.refresh.saturating_sub(age)
        }
        None => Duration::ZERO,
    }
}

/// Keeps one list fresh forever: restores its cache, then downloads whenever it is due, waiting
/// `retry` after a failure. Failures keep the last good copy. Run one per enabled list.
pub async fn keep_fresh(
    list: HttpList,
    fetch: std::sync::Arc<dyn Fetch>,
    remote: RemoteLists,
    dir: PathBuf,
    cap: usize,
) {
    let mut wait = restore(&list, &remote, &dir);
    loop {
        tokio::time::sleep(wait).await;
        wait = match refresh(&list, fetch.as_ref(), &remote, &dir, cap).await {
            Ok(keys) => {
                tracing::info!(list = %list.name, keys, "list refreshed");
                list.refresh
            }
            Err(error) => {
                tracing::warn!(list = %list.name, %error, "list refresh failed");
                list.retry
            }
        };
    }
}

#[cfg(test)]
mod tests;
