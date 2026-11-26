//! The state snapshot file: every live key of the in-memory state with its absolute expiry.

use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, bail};
use pellet_state::Key;

const MAGIC: &[u8; 8] = b"PELLETS1";

type Entry = (Key, Vec<u8>, Option<Duration>);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Writes entries atomically: a temporary file next to `path`, then a rename. Expiry is stored
/// as Unix seconds so time spent stopped counts.
pub fn save(path: &Path, entries: &[Entry]) -> anyhow::Result<()> {
    let now = now();
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for (key, value, ttl) in entries {
        let key = key.as_str().as_bytes();
        out.extend_from_slice(&(key.len() as u16).to_le_bytes());
        out.extend_from_slice(key);
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
        let expiry = ttl.map_or(0, |t| now + t.as_secs().max(1));
        out.extend_from_slice(&expiry.to_le_bytes());
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, out).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}

/// Reads a snapshot; entries that expired meanwhile are left out.
pub fn load(path: &Path) -> anyhow::Result<Vec<Entry>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    parse(&bytes, now()).with_context(|| format!("loading {}", path.display()))
}

fn parse(bytes: &[u8], now: u64) -> anyhow::Result<Vec<Entry>> {
    let mut at = 0usize;
    let mut take = |n: usize| -> anyhow::Result<&[u8]> {
        let slice = bytes.get(at..at + n).context("truncated snapshot")?;
        at += n;
        Ok(slice)
    };
    if take(8)? != MAGIC {
        bail!("not a state snapshot");
    }
    let count = u64::from_le_bytes(take(8)?.try_into()?);
    let mut entries = Vec::new();
    for _ in 0..count {
        let key_len = u16::from_le_bytes(take(2)?.try_into()?) as usize;
        let key = Key::new(String::from_utf8(take(key_len)?.to_vec())?)?;
        let value_len = u32::from_le_bytes(take(4)?.try_into()?) as usize;
        let value = take(value_len)?.to_vec();
        let expiry = u64::from_le_bytes(take(8)?.try_into()?);
        let ttl = match expiry {
            0 => None,
            e if e <= now => continue,
            e => Some(Duration::from_secs(e - now)),
        };
        entries.push((key, value, ttl));
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(s: &str) -> Key {
        Key::new(s).unwrap()
    }

    #[test]
    fn round_trip_and_expiry() {
        let dir = std::env::temp_dir().join(format!("pellet-snapshot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.bin");
        let entries = vec![
            (
                key("rep/ip/192.0.2.1"),
                vec![1, 0, 0, 0, 2, 0, 0, 0],
                Some(Duration::from_secs(3600)),
            ),
            (key("forever"), b"x".to_vec(), None),
        ];
        save(&path, &entries).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[1], (key("forever"), b"x".to_vec(), None));
        assert!(loaded[0].2.unwrap() <= Duration::from_secs(3600));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn expired_and_broken_snapshots() {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&3u16.to_le_bytes());
        bytes.extend_from_slice(b"old");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(7);
        bytes.extend_from_slice(&100u64.to_le_bytes());
        assert!(
            parse(&bytes, 200).unwrap().is_empty(),
            "expired while stopped"
        );
        assert_eq!(
            parse(&bytes, 50).unwrap()[0].2,
            Some(Duration::from_secs(50))
        );
        assert!(parse(&bytes[..bytes.len() - 1], 50).is_err());
        assert!(parse(b"garbage!", 0).is_err());
    }
}
