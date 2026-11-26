//! Download contract for remote lists: one body per URL, within a deadline and a size limit.

use std::time::Duration;

use async_trait::async_trait;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// Why a body could not be downloaded. `Display` never carries the URL.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// The URL is unusable, the connection failed, the deadline passed, or the server answered
    /// with an error status.
    #[error("download failed: {0}")]
    Download(String),
    /// The body is larger than the given limit.
    #[error("larger than {0} bytes")]
    TooLarge(usize),
}

/// Downloads a list body.
///
/// Guarantees an implementation must keep:
/// - `Ok` holds the whole body exactly as served, never more than `max_size` bytes.
/// - A body longer than `max_size` is [`FetchError::TooLarge`] with `max_size`, and reading
///   stops there.
/// - An error status, an unusable URL or a failed connection is [`FetchError::Download`].
/// - The call ends within `timeout` plus scheduling slack, as [`FetchError::Download`] at worst.
/// - Error messages never contain the URL.
#[async_trait]
pub trait Fetch: Send + Sync {
    /// The body at `url`, read within `timeout`, refused beyond `max_size` bytes.
    async fn fetch(
        &self,
        url: &str,
        timeout: Duration,
        max_size: usize,
    ) -> Result<Vec<u8>, FetchError>;
}

#[cfg(test)]
mod tests;
