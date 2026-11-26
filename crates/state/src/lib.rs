//! State contract: expiring keys with compare-and-swap for caches, reputation, greylisting and models.
//!
//! Expiry runs on the Tokio clock, so suites and checks can be tested on paused time.

use std::{fmt, time::Duration};

use async_trait::async_trait;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// Longest accepted key, in bytes.
pub const MAX_KEY_LEN: usize = 256;
/// Largest accepted value, in bytes.
pub const MAX_VALUE_LEN: usize = 32 * 1024 * 1024;

/// A state key such as `rep/ip/192.0.2.7`.
///
/// Guaranteed to be 1 to [`MAX_KEY_LEN`] bytes without control characters. Keys are compared byte
/// for byte.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key(String);

impl Key {
    /// Validates a key.
    pub fn new(key: impl Into<String>) -> Result<Self, StateError> {
        let key = key.into();
        if key.is_empty() || key.len() > MAX_KEY_LEN || key.chars().any(char::is_control) {
            return Err(StateError::InvalidKey);
        }
        Ok(Key(key))
    }

    /// The key as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An opaque version of a stored value. A key never gets the same version twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Version(pub u64);

/// A stored value and its version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The bytes as written.
    pub value: Vec<u8>,
    /// The version the write produced.
    pub version: Version,
}

/// The condition a write needs to succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// Write regardless of the current value.
    Any,
    /// Write only if the key holds nothing (or only an expired value).
    Absent,
    /// Write only if the key holds exactly this version.
    Version(Version),
}

/// Why a state operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StateError {
    /// The key is empty, too long or has control characters.
    #[error("invalid state key")]
    InvalidKey,
    /// The value is larger than [`MAX_VALUE_LEN`].
    #[error("state value too large")]
    TooLarge,
    /// The expectation did not hold; nothing was written.
    #[error("state changed concurrently")]
    Conflict,
    /// The backend could not be reached; nothing is known about the outcome of a write.
    #[error("state unavailable: {0}")]
    Unavailable(String),
}

/// Small durable-or-not key–value state.
///
/// Guarantees an implementation must keep:
/// - Read-after-write: a `get` after a successful `put` or `delete` sees its effect.
/// - `put` and `delete` with [`Expect::Absent`] or [`Expect::Version`] are compare-and-swap: of
///   concurrent writes with the same expectation, at most one succeeds and the rest get
///   [`StateError::Conflict`].
/// - A value with a time to live is gone once it has elapsed on the Tokio clock; until then it may
///   also be dropped early (an implementation with a size cap evicts). Losing such a key must be
///   harmless to every caller.
/// - A value without a time to live may still be evicted by an implementation that says so.
/// - Values come back byte for byte.
#[async_trait]
pub trait State: Send + Sync {
    /// The live value of a key.
    async fn get(&self, key: &Key) -> Result<Option<Entry>, StateError>;

    /// Writes a value if `expect` holds and returns its new version.
    async fn put(
        &self,
        key: &Key,
        value: Vec<u8>,
        expect: Expect,
        ttl: Option<Duration>,
    ) -> Result<Version, StateError>;

    /// Removes a key if `expect` holds; `Ok(false)` when there was nothing live to remove.
    async fn delete(&self, key: &Key, expect: Expect) -> Result<bool, StateError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_validated() {
        assert!(Key::new("rep/ip/192.0.2.7").is_ok());
        assert_eq!(Key::new(""), Err(StateError::InvalidKey));
        assert_eq!(Key::new("a\nb"), Err(StateError::InvalidKey));
        assert!(Key::new("k".repeat(MAX_KEY_LEN)).is_ok());
        assert_eq!(
            Key::new("k".repeat(MAX_KEY_LEN + 1)),
            Err(StateError::InvalidKey)
        );
    }
}
