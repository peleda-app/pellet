//! `Resolver` backed by hickory-resolver with a bounded cache and a deadline per call.

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use async_trait::async_trait;
use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    net::{NetError, runtime::TokioRuntimeProvider},
    proto::rr::{Name, RData},
    system_conf::read_system_conf,
};
use pellet_dns::{DnsError, Resolver, is_reserved_invalid, normalize};

/// How to reach DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HickoryConfig {
    /// Recursive resolvers to ask on port 53 over UDP and TCP; empty means the system
    /// configuration. A local resolver is recommended: some DNS lists refuse public ones.
    pub nameservers: Vec<IpAddr>,
    /// Longest time one call may take, retries included.
    pub deadline: Duration,
    /// Most answers kept in the cache; answers expire with their TTL.
    pub cache_size: u64,
}

impl Default for HickoryConfig {
    fn default() -> Self {
        HickoryConfig {
            nameservers: Vec::new(),
            deadline: Duration::from_secs(2),
            cache_size: 4096,
        }
    }
}

/// The resolver could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot build the DNS resolver: {0}")]
pub struct BuildError(String);

/// `Resolver` over hickory-resolver.
///
/// Names are validated and `.invalid` names answered before anything is sent. Every call is cut
/// off at the configured deadline. Answers, including negative ones, are cached by hickory up to
/// `cache_size` entries for their TTL.
pub struct HickoryResolver {
    inner: TokioResolver,
    deadline: Duration,
}

impl HickoryResolver {
    /// Builds a resolver; no query is sent until the first lookup.
    pub fn new(config: &HickoryConfig) -> Result<Self, BuildError> {
        let (resolver_config, mut options) = if config.nameservers.is_empty() {
            read_system_conf().map_err(|e| BuildError(e.to_string()))?
        } else {
            let servers = config
                .nameservers
                .iter()
                .map(|ip| NameServerConfig::udp_and_tcp(*ip))
                .collect();
            (
                ResolverConfig::from_name_servers(servers),
                ResolverOpts::default(),
            )
        };
        options.cache_size = config.cache_size;
        options.timeout = config.deadline.min(options.timeout);
        let inner =
            TokioResolver::builder_with_config(resolver_config, TokioRuntimeProvider::default())
                .with_options(options)
                .build()
                .map_err(|e| BuildError(e.to_string()))?;
        Ok(HickoryResolver {
            inner,
            deadline: config.deadline,
        })
    }

    fn name(name: &str) -> Result<Name, DnsError> {
        let name = normalize(name)?;
        if is_reserved_invalid(&name) {
            return Err(DnsError::NotFound);
        }
        Name::from_ascii(format!("{name}.")).map_err(|_| DnsError::InvalidName)
    }

    async fn run<T, L>(
        &self,
        lookup: impl Future<Output = Result<L, NetError>>,
        extract: impl FnOnce(L) -> Vec<T>,
    ) -> Result<Vec<T>, DnsError> {
        match tokio::time::timeout(self.deadline, lookup).await {
            Err(_) => Err(DnsError::Timeout),
            Ok(Err(error)) => Err(map_error(&error)),
            Ok(Ok(answer)) => {
                let records = extract(answer);
                if records.is_empty() {
                    Err(DnsError::NotFound)
                } else {
                    Ok(records)
                }
            }
        }
    }
}

fn map_error(error: &NetError) -> DnsError {
    if error.is_no_records_found() || error.is_nx_domain() {
        DnsError::NotFound
    } else if matches!(error, NetError::Timeout) {
        DnsError::Timeout
    } else {
        DnsError::Failed(error.to_string())
    }
}

fn host(name: &Name) -> String {
    let ascii = name.to_lowercase().to_ascii();
    ascii.strip_suffix('.').unwrap_or(&ascii).to_string()
}

#[async_trait]
impl Resolver for HickoryResolver {
    async fn ipv4(&self, name: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        let name = Self::name(name)?;
        self.run(self.inner.ipv4_lookup(name), |lookup| {
            lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::A(a) => Some(a.0),
                    _ => None,
                })
                .collect()
        })
        .await
    }

    async fn ipv6(&self, name: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        let name = Self::name(name)?;
        self.run(self.inner.ipv6_lookup(name), |lookup| {
            lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::AAAA(aaaa) => Some(aaaa.0),
                    _ => None,
                })
                .collect()
        })
        .await
    }

    async fn txt(&self, name: &str) -> Result<Vec<Vec<u8>>, DnsError> {
        let name = Self::name(name)?;
        self.run(self.inner.txt_lookup(name), |lookup| {
            lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::TXT(txt) => Some(
                        txt.txt_data
                            .iter()
                            .flat_map(|c| c.iter().copied())
                            .collect(),
                    ),
                    _ => None,
                })
                .collect()
        })
        .await
    }

    async fn mx(&self, name: &str) -> Result<Vec<(u16, String)>, DnsError> {
        let name = Self::name(name)?;
        self.run(self.inner.mx_lookup(name), |lookup| {
            lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::MX(mx) => Some((mx.preference, host(&mx.exchange))),
                    _ => None,
                })
                .collect()
        })
        .await
    }

    async fn ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        self.run(self.inner.reverse_lookup(ip), |lookup| {
            lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::PTR(ptr) if !ptr.is_empty() => Some(host(ptr)),
                    _ => None,
                })
                .collect()
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offline_resolver() -> HickoryResolver {
        HickoryResolver::new(&HickoryConfig {
            nameservers: vec!["192.0.2.53".parse().unwrap()],
            ..HickoryConfig::default()
        })
        .unwrap()
    }

    #[tokio::test]
    async fn passes_offline_conformance() {
        pellet_dns::testing::offline(&offline_resolver()).await;
    }

    #[test]
    fn names_are_fully_qualified() {
        let name = HickoryResolver::name("Mail.Example.org").unwrap();
        assert!(name.is_fqdn());
        assert_eq!(host(&name), "mail.example.org");
    }

    #[test]
    fn default_config_is_bounded() {
        let config = HickoryConfig::default();
        assert!(config.cache_size > 0);
        assert!(config.deadline <= Duration::from_secs(5));
    }
}
