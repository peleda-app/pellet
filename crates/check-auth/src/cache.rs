use std::{
    borrow::Borrow,
    collections::HashMap,
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Mutex,
    time::Instant,
};

use mail_auth::{DnsCache, Mx, Negative, RecordSet, ResolverCache, TxtRecord};

type Answer<T> = Result<RecordSet<T>, Negative>;

/// A cache with a cap on entries that honors the expiry of every answer.
///
/// When full, expired entries go first, then half of the rest, so the cost of eviction is spread
/// over many inserts.
pub(crate) struct BoundedCache<K, V> {
    entries: Mutex<HashMap<K, (V, Instant)>>,
    cap: usize,
}

impl<K: Hash + Eq, V: Clone> BoundedCache<K, V> {
    fn new(cap: usize) -> Self {
        BoundedCache {
            entries: Mutex::new(HashMap::new()),
            cap: cap.max(1),
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

impl<K: Hash + Eq, V: Clone> ResolverCache<K, V> for BoundedCache<K, V> {
    fn get<Q>(&self, name: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries
            .get(name)
            .filter(|(_, until)| Instant::now() < *until)
            .map(|(value, _)| value.clone())
    }

    fn remove<Q>(&self, name: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries.remove(name).map(|(value, _)| value)
    }

    fn insert(&self, key: K, value: V, valid_until: Instant) {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        if entries.len() >= self.cap && !entries.contains_key(&key) {
            let now = Instant::now();
            entries.retain(|_, (_, until)| now < *until);
            if entries.len() >= self.cap {
                let mut keep = false;
                entries.retain(|_, _| {
                    keep = !keep;
                    keep
                });
            }
        }
        entries.insert(key, (value, valid_until));
    }
}

/// One bounded cache per record type, as `mail-auth` expects.
pub(crate) struct AuthCache {
    pub(crate) txt: BoundedCache<Box<str>, TxtRecord>,
    pub(crate) mx: BoundedCache<Box<str>, Answer<Mx>>,
    pub(crate) ipv4: BoundedCache<Box<str>, Answer<Ipv4Addr>>,
    pub(crate) ipv6: BoundedCache<Box<str>, Answer<Ipv6Addr>>,
    pub(crate) ptr: BoundedCache<IpAddr, Answer<Box<str>>>,
}

impl AuthCache {
    pub(crate) fn new(cap: usize) -> Self {
        AuthCache {
            txt: BoundedCache::new(cap),
            mx: BoundedCache::new(cap),
            ipv4: BoundedCache::new(cap),
            ipv6: BoundedCache::new(cap),
            ptr: BoundedCache::new(cap),
        }
    }
}

impl DnsCache for AuthCache {
    type Txt = BoundedCache<Box<str>, TxtRecord>;
    type Mx = BoundedCache<Box<str>, Answer<Mx>>;
    type Ipv4 = BoundedCache<Box<str>, Answer<Ipv4Addr>>;
    type Ipv6 = BoundedCache<Box<str>, Answer<Ipv6Addr>>;
    type Ptr = BoundedCache<IpAddr, Answer<Box<str>>>;

    fn txt(&self) -> Option<&Self::Txt> {
        Some(&self.txt)
    }

    fn mx(&self) -> Option<&Self::Mx> {
        Some(&self.mx)
    }

    fn ipv4(&self) -> Option<&Self::Ipv4> {
        Some(&self.ipv4)
    }

    fn ipv6(&self) -> Option<&Self::Ipv6> {
        Some(&self.ipv6)
    }

    fn ptr(&self) -> Option<&Self::Ptr> {
        Some(&self.ptr)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn later() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    #[test]
    fn returns_live_entries_only() {
        let cache: BoundedCache<String, u32> = BoundedCache::new(10);
        cache.insert("live".into(), 1, later());
        cache.insert("dead".into(), 2, Instant::now() - Duration::from_secs(1));
        assert_eq!(cache.get("live"), Some(1));
        assert_eq!(cache.get("dead"), None);
        assert_eq!(cache.remove("live"), Some(1));
        assert_eq!(cache.get("live"), None);
    }

    #[test]
    fn never_grows_past_the_cap() {
        let cache: BoundedCache<u32, u32> = BoundedCache::new(8);
        for i in 0..100 {
            cache.insert(i, i, later());
            assert!(cache.len() <= 8);
        }
        assert_eq!(cache.get(&99), Some(99), "the newest entry is kept");
    }

    #[test]
    fn expired_entries_are_evicted_before_live_ones() {
        let cache: BoundedCache<u32, u32> = BoundedCache::new(3);
        cache.insert(1, 1, Instant::now() - Duration::from_secs(1));
        cache.insert(2, 2, later());
        cache.insert(3, 3, later());
        cache.insert(4, 4, later());
        assert_eq!(cache.get(&2), Some(2));
        assert_eq!(cache.get(&3), Some(3));
        assert_eq!(cache.get(&4), Some(4));
    }
}
