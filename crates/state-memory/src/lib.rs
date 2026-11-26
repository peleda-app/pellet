//! `State` kept in memory; nothing survives the process.

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
    time::Duration,
};

use async_trait::async_trait;
use pellet_state::{Entry, Expect, Key, MAX_VALUE_LEN, State, StateError, Version};
use tokio::time::Instant;

struct Item {
    value: Vec<u8>,
    version: u64,
    expires: Option<Instant>,
    used: u64,
}

impl Item {
    fn live(&self, now: Instant) -> bool {
        self.expires.is_none_or(|at| now < at)
    }
}

#[derive(Default)]
struct Inner {
    items: HashMap<Key, Item>,
    next_version: u64,
    clock: u64,
}

impl Inner {
    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn live_version(&self, key: &Key, now: Instant) -> Option<u64> {
        self.items
            .get(key)
            .filter(|item| item.live(now))
            .map(|item| item.version)
    }

    fn evict(&mut self, cap: usize, now: Instant) {
        self.items.retain(|_, item| item.live(now));
        if self.items.len() < cap {
            return;
        }
        let excess = self.items.len() + 1 - cap;
        let batch = excess.max(cap / 8).max(1).min(self.items.len());
        let mut ages: Vec<(u64, Key)> = self
            .items
            .iter()
            .map(|(key, item)| (item.used, key.clone()))
            .collect();
        ages.select_nth_unstable_by_key(batch - 1, |(used, _)| *used);
        for (_, key) in ages.into_iter().take(batch) {
            self.items.remove(&key);
        }
    }
}

/// `State` in memory with a cap on the number of keys.
///
/// When a new key would pass the cap, expired keys go first, then the least recently used ones in
/// a batch of about an eighth of the cap, so eviction cost is spread over many writes. Any key may
/// be evicted, with or without a time to live. Versions come from one counter and are never reused.
pub struct MemoryState {
    inner: Mutex<Inner>,
    cap: usize,
}

impl MemoryState {
    /// A store holding at most `cap` keys (at least one).
    pub fn new(cap: usize) -> Self {
        MemoryState {
            inner: Mutex::new(Inner::default()),
            cap: cap.max(1),
        }
    }

    /// Number of keys held, including expired ones not yet removed.
    pub fn len(&self) -> usize {
        self.lock().items.len()
    }

    /// Whether no keys are held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every live key with its value and remaining time to live, for a host to keep elsewhere.
    pub fn export(&self) -> Vec<(Key, Vec<u8>, Option<Duration>)> {
        let now = Instant::now();
        self.lock()
            .items
            .iter()
            .filter(|(_, item)| item.live(now))
            .map(|(key, item)| {
                (
                    key.clone(),
                    item.value.clone(),
                    item.expires.map(|at| at.saturating_duration_since(now)),
                )
            })
            .collect()
    }

    /// Writes entries as unconditional puts, as from an earlier [`MemoryState::export`]; the
    /// cap still applies, so later entries may push out earlier ones.
    pub fn import(&self, entries: impl IntoIterator<Item = (Key, Vec<u8>, Option<Duration>)>) {
        let now = Instant::now();
        let mut inner = self.lock();
        for (key, value, ttl) in entries {
            if value.len() > MAX_VALUE_LEN || ttl.is_some_and(|t| t.is_zero()) {
                continue;
            }
            if !inner.items.contains_key(&key) && inner.items.len() >= self.cap {
                inner.evict(self.cap, now);
            }
            inner.next_version += 1;
            let version = inner.next_version;
            let used = inner.tick();
            inner.items.insert(
                key,
                Item {
                    value,
                    version,
                    expires: ttl.map(|ttl| now + ttl),
                    used,
                },
            );
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn holds(current: Option<u64>, expect: Expect) -> bool {
    match expect {
        Expect::Any => true,
        Expect::Absent => current.is_none(),
        Expect::Version(Version(v)) => current == Some(v),
    }
}

#[async_trait]
impl State for MemoryState {
    async fn get(&self, key: &Key) -> Result<Option<Entry>, StateError> {
        let now = Instant::now();
        let mut inner = self.lock();
        let tick = inner.tick();
        Ok(inner
            .items
            .get_mut(key)
            .filter(|item| item.live(now))
            .map(|item| {
                item.used = tick;
                Entry {
                    value: item.value.clone(),
                    version: Version(item.version),
                }
            }))
    }

    async fn put(
        &self,
        key: &Key,
        value: Vec<u8>,
        expect: Expect,
        ttl: Option<Duration>,
    ) -> Result<Version, StateError> {
        if value.len() > MAX_VALUE_LEN {
            return Err(StateError::TooLarge);
        }
        let now = Instant::now();
        let mut inner = self.lock();
        if !holds(inner.live_version(key, now), expect) {
            return Err(StateError::Conflict);
        }
        if !inner.items.contains_key(key) && inner.items.len() >= self.cap {
            inner.evict(self.cap, now);
        }
        inner.next_version += 1;
        let version = inner.next_version;
        let used = inner.tick();
        inner.items.insert(
            key.clone(),
            Item {
                value,
                version,
                expires: ttl.map(|ttl| now + ttl),
                used,
            },
        );
        Ok(Version(version))
    }

    async fn delete(&self, key: &Key, expect: Expect) -> Result<bool, StateError> {
        let now = Instant::now();
        let mut inner = self.lock();
        let current = inner.live_version(key, now);
        if !holds(current, expect) {
            return Err(StateError::Conflict);
        }
        inner.items.remove(key);
        Ok(current.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: usize) -> Key {
        Key::new(format!("k{n}")).unwrap()
    }

    #[tokio::test]
    async fn conformance() {
        pellet_state::testing::conformance(&MemoryState::new(1000)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn expiry() {
        pellet_state::testing::expiry(&MemoryState::new(1000)).await;
    }

    #[tokio::test]
    async fn never_holds_more_than_the_cap() {
        let state = MemoryState::new(16);
        for n in 0..200 {
            state
                .put(&key(n), vec![1], Expect::Any, None)
                .await
                .unwrap();
            assert!(state.len() <= 16, "len {} after {n}", state.len());
        }
        assert!(
            state.get(&key(199)).await.unwrap().is_some(),
            "newest key survives"
        );
    }

    #[tokio::test]
    async fn evicts_least_recently_used_first() {
        let state = MemoryState::new(8);
        for n in 0..8 {
            state
                .put(&key(n), vec![1], Expect::Any, None)
                .await
                .unwrap();
        }
        state.get(&key(0)).await.unwrap();
        state
            .put(&key(100), vec![1], Expect::Any, None)
            .await
            .unwrap();
        assert!(
            state.get(&key(0)).await.unwrap().is_some(),
            "recently read key kept"
        );
        assert!(
            state.get(&key(1)).await.unwrap().is_none(),
            "oldest untouched key evicted"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn evicts_expired_before_live() {
        let state = MemoryState::new(4);
        state
            .put(&key(0), vec![1], Expect::Any, Some(Duration::from_secs(1)))
            .await
            .unwrap();
        for n in 1..4 {
            state
                .put(&key(n), vec![1], Expect::Any, None)
                .await
                .unwrap();
        }
        tokio::time::advance(Duration::from_secs(2)).await;
        state
            .put(&key(10), vec![1], Expect::Any, None)
            .await
            .unwrap();
        for n in 1..4 {
            assert!(
                state.get(&key(n)).await.unwrap().is_some(),
                "live key {n} kept"
            );
        }
    }

    #[tokio::test]
    async fn overwriting_at_the_cap_evicts_nothing() {
        let state = MemoryState::new(2);
        state
            .put(&key(0), vec![1], Expect::Any, None)
            .await
            .unwrap();
        state
            .put(&key(1), vec![1], Expect::Any, None)
            .await
            .unwrap();
        state
            .put(&key(0), vec![2], Expect::Any, None)
            .await
            .unwrap();
        assert!(state.get(&key(1)).await.unwrap().is_some());
        assert_eq!(state.len(), 2);
    }

    #[tokio::test]
    async fn concurrent_compare_and_swap_has_one_winner() {
        let state = std::sync::Arc::new(MemoryState::new(10));
        let k = key(0);
        let base = state.put(&k, vec![0], Expect::Any, None).await.unwrap();
        let tasks: Vec<_> = (0..16u8)
            .map(|i| {
                let state = state.clone();
                let k = k.clone();
                tokio::spawn(
                    async move { state.put(&k, vec![i], Expect::Version(base), None).await },
                )
            })
            .collect();
        let mut wins = 0;
        for task in tasks {
            if task.await.unwrap().is_ok() {
                wins += 1;
            }
        }
        assert_eq!(wins, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn export_and_import_keep_values_and_remaining_ttl() {
        let source = MemoryState::new(10);
        source
            .put(&key(1), b"one".to_vec(), Expect::Any, None)
            .await
            .unwrap();
        source
            .put(
                &key(2),
                b"two".to_vec(),
                Expect::Any,
                Some(Duration::from_secs(100)),
            )
            .await
            .unwrap();
        source
            .put(
                &key(3),
                b"gone".to_vec(),
                Expect::Any,
                Some(Duration::from_secs(1)),
            )
            .await
            .unwrap();
        tokio::time::advance(Duration::from_secs(10)).await;
        let mut exported = source.export();
        exported.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(exported.len(), 2, "expired keys are not exported");
        assert_eq!(exported[1].2, Some(Duration::from_secs(90)));

        let target = MemoryState::new(10);
        target.import(exported);
        assert_eq!(target.get(&key(1)).await.unwrap().unwrap().value, b"one");
        tokio::time::advance(Duration::from_secs(89)).await;
        assert!(target.get(&key(2)).await.unwrap().is_some());
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(target.get(&key(2)).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn import_respects_the_cap() {
        let target = MemoryState::new(4);
        target.import((0..20).map(|n| (key(n), vec![1], None)));
        assert!(target.len() <= 4);
        assert!(target.get(&key(19)).await.unwrap().is_some());
        target.import([(key(50), vec![0; 4], Some(Duration::ZERO))]);
        assert!(
            target.get(&key(50)).await.unwrap().is_none(),
            "zero time to live is skipped"
        );
    }
}
