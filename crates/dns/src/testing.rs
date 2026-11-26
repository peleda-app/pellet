//! A fake resolver and the offline conformance suite for the `Resolver` contract.
//!
//! ```ignore
//! #[tokio::test]
//! async fn conformance() {
//!     pellet_dns::testing::offline(&MyResolver::new()).await;
//! }
//! ```

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;

use crate::{DnsError, Resolver, is_reserved_invalid, normalize};

/// Checks what every resolver must do without touching the network: invalid names refused,
/// `.invalid` names not found.
pub async fn offline(resolver: &dyn Resolver) {
    for bad in ["", "a..b", "has space.example", "-x.example"] {
        assert_eq!(
            resolver.ipv4(bad).await,
            Err(DnsError::InvalidName),
            "A {bad:?}"
        );
        assert_eq!(
            resolver.ipv6(bad).await,
            Err(DnsError::InvalidName),
            "AAAA {bad:?}"
        );
        assert_eq!(
            resolver.txt(bad).await,
            Err(DnsError::InvalidName),
            "TXT {bad:?}"
        );
        assert_eq!(
            resolver.mx(bad).await,
            Err(DnsError::InvalidName),
            "MX {bad:?}"
        );
    }
    for reserved in ["host.invalid", "INVALID."] {
        assert_eq!(resolver.ipv4(reserved).await, Err(DnsError::NotFound));
        assert_eq!(resolver.ipv6(reserved).await, Err(DnsError::NotFound));
        assert_eq!(resolver.txt(reserved).await, Err(DnsError::NotFound));
        assert_eq!(resolver.mx(reserved).await, Err(DnsError::NotFound));
    }
}

#[derive(Default)]
struct Records {
    ipv4: HashMap<String, Vec<Ipv4Addr>>,
    ipv6: HashMap<String, Vec<Ipv6Addr>>,
    txt: HashMap<String, Vec<Vec<u8>>>,
    mx: HashMap<String, Vec<(u16, String)>>,
    ptr: HashMap<IpAddr, Vec<String>>,
    errors: HashMap<String, DnsError>,
}

/// A resolver answering from records set in code. Unknown names are [`DnsError::NotFound`].
#[derive(Default)]
pub struct FakeResolver {
    records: Mutex<Records>,
    queries: AtomicUsize,
}

impl FakeResolver {
    /// A resolver with no records.
    pub fn new() -> Self {
        Self::default()
    }

    fn with(self, f: impl FnOnce(&mut Records)) -> Self {
        f(&mut self.records.lock().unwrap());
        self
    }

    fn key(name: &str) -> String {
        normalize(name).expect("fake records use valid names")
    }

    /// Adds A records.
    pub fn with_ipv4(self, name: &str, ips: &[&str]) -> Self {
        let ips = ips.iter().map(|ip| ip.parse().unwrap()).collect();
        self.with(|r| {
            r.ipv4.insert(Self::key(name), ips);
        })
    }

    /// Adds AAAA records.
    pub fn with_ipv6(self, name: &str, ips: &[&str]) -> Self {
        let ips = ips.iter().map(|ip| ip.parse().unwrap()).collect();
        self.with(|r| {
            r.ipv6.insert(Self::key(name), ips);
        })
    }

    /// Adds TXT records.
    pub fn with_txt(self, name: &str, records: &[&str]) -> Self {
        let records = records.iter().map(|t| t.as_bytes().to_vec()).collect();
        self.with(|r| {
            r.txt.insert(Self::key(name), records);
        })
    }

    /// Adds MX records.
    pub fn with_mx(self, name: &str, records: &[(u16, &str)]) -> Self {
        let records = records.iter().map(|(p, h)| (*p, h.to_string())).collect();
        self.with(|r| {
            r.mx.insert(Self::key(name), records);
        })
    }

    /// Adds PTR records.
    pub fn with_ptr(self, ip: &str, names: &[&str]) -> Self {
        let names = names.iter().map(|n| Self::key(n)).collect();
        self.with(|r| {
            r.ptr.insert(ip.parse().unwrap(), names);
        })
    }

    /// Makes every lookup of `name` (or of the address `name` for PTR) fail with `error`.
    pub fn with_error(self, name: &str, error: DnsError) -> Self {
        let key = name
            .parse::<IpAddr>()
            .map_or_else(|_| Self::key(name), |ip| ip.to_string());
        self.with(|r| {
            r.errors.insert(key, error);
        })
    }

    /// Lookups that reached the records, not counting refused or reserved names.
    pub fn queries(&self) -> usize {
        self.queries.load(Ordering::Relaxed)
    }

    fn lookup<T: Clone>(
        &self,
        name: &str,
        pick: impl FnOnce(&Records) -> Option<&Vec<T>>,
    ) -> Result<Vec<T>, DnsError> {
        let name = normalize(name)?;
        if is_reserved_invalid(&name) {
            return Err(DnsError::NotFound);
        }
        self.queries.fetch_add(1, Ordering::Relaxed);
        let records = self.records.lock().unwrap();
        if let Some(error) = records.errors.get(&name) {
            return Err(error.clone());
        }
        match pick(&records) {
            Some(found) if !found.is_empty() => Ok(found.clone()),
            _ => Err(DnsError::NotFound),
        }
    }
}

#[async_trait]
impl Resolver for FakeResolver {
    async fn ipv4(&self, name: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        let key = normalize(name).unwrap_or_default();
        self.lookup(name, |r| r.ipv4.get(&key))
    }

    async fn ipv6(&self, name: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        let key = normalize(name).unwrap_or_default();
        self.lookup(name, |r| r.ipv6.get(&key))
    }

    async fn txt(&self, name: &str) -> Result<Vec<Vec<u8>>, DnsError> {
        let key = normalize(name).unwrap_or_default();
        self.lookup(name, |r| r.txt.get(&key))
    }

    async fn mx(&self, name: &str) -> Result<Vec<(u16, String)>, DnsError> {
        let key = normalize(name).unwrap_or_default();
        self.lookup(name, |r| r.mx.get(&key))
    }

    async fn ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        self.queries.fetch_add(1, Ordering::Relaxed);
        let records = self.records.lock().unwrap();
        if let Some(error) = records.errors.get(&ip.to_string()) {
            return Err(error.clone());
        }
        match records.ptr.get(&ip) {
            Some(found) if !found.is_empty() => Ok(found.clone()),
            _ => Err(DnsError::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fake_passes_offline_conformance() {
        offline(&FakeResolver::new()).await;
    }

    #[tokio::test]
    async fn answers_from_records() {
        let resolver = FakeResolver::new()
            .with_ipv4("Mail.Example.org", &["192.0.2.1"])
            .with_txt("example.org", &["v=spf1 -all"])
            .with_mx("example.org", &[(10, "mx.example.org")])
            .with_ptr("192.0.2.1", &["Mail.Example.org."])
            .with_error("broken.example", DnsError::Timeout);
        assert_eq!(
            resolver.ipv4("mail.example.org.").await.unwrap(),
            ["192.0.2.1".parse::<Ipv4Addr>().unwrap()]
        );
        assert_eq!(
            resolver.txt("EXAMPLE.org").await.unwrap(),
            [b"v=spf1 -all".to_vec()]
        );
        assert_eq!(resolver.mx("example.org").await.unwrap()[0].0, 10);
        assert_eq!(
            resolver.ptr("192.0.2.1".parse().unwrap()).await.unwrap(),
            ["mail.example.org"]
        );
        assert_eq!(
            resolver.ipv6("mail.example.org").await,
            Err(DnsError::NotFound)
        );
        assert_eq!(
            resolver.ipv4("broken.example").await,
            Err(DnsError::Timeout)
        );
        assert_eq!(resolver.queries(), 6);
    }
}
