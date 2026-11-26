use std::{net::IpAddr, ops::RangeInclusive, sync::Arc};

use async_trait::async_trait;
use futures::future::join_all;
use pellet_check::{Check, CheckError, Context};
use pellet_core::{Stage, Symbol, SymbolName};
use pellet_dns::{Resolver, list_query};

use crate::is_listable;

/// One answer code a list returns and the symbol it means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsblResult {
    /// Last octet of the `127.0.0.x` answer, as a range.
    pub codes: RangeInclusive<u8>,
    /// The symbol to emit.
    pub symbol: SymbolName,
}

/// A DNS list queried by client address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsblZone {
    /// The zone, such as `zen.example.org`.
    pub zone: String,
    /// Whether the zone lists IPv6 addresses; IPv4-only zones are not asked about IPv6.
    pub ipv6: bool,
    /// What its answers mean.
    pub results: Vec<DnsblResult>,
}

/// DNS blocklists at [`Stage::Connect`].
///
/// Every zone is asked concurrently. Only answers inside `127.0.0.0/8` count, so a wildcard or
/// hijacked NXDOMAIN never lists anyone; an answer whose code no result covers emits nothing.
/// Symbols carry the zone as their option. When every zone fails to answer the check reports a
/// temporary error; otherwise failed zones are left out.
pub struct DnsblCheck {
    resolver: Arc<dyn Resolver>,
    zones: Vec<DnsblZone>,
    declared: Vec<SymbolName>,
}

impl DnsblCheck {
    /// Builds the check from its zones.
    pub fn new(resolver: Arc<dyn Resolver>, zones: Vec<DnsblZone>) -> Self {
        let mut declared: Vec<SymbolName> = zones
            .iter()
            .flat_map(|z| z.results.iter().map(|r| r.symbol.clone()))
            .collect();
        declared.sort();
        declared.dedup();
        DnsblCheck {
            resolver,
            zones,
            declared,
        }
    }
}

#[async_trait]
impl Check for DnsblCheck {
    fn name(&self) -> &str {
        "ip.dnsbl"
    }

    fn stage(&self) -> Stage {
        Stage::Connect
    }

    fn symbols(&self) -> &[SymbolName] {
        &self.declared
    }

    async fn run(&self, ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError> {
        let Some(ip) = ctx.envelope.client_ip else {
            return Ok(Vec::new());
        };
        if ctx.envelope.authenticated || !is_listable(ip) {
            return Ok(Vec::new());
        }
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        let zones: Vec<&DnsblZone> = self
            .zones
            .iter()
            .filter(|z| ip.is_ipv4() || z.ipv6)
            .collect();
        let queries: Vec<String> = zones.iter().map(|z| list_query(ip, &z.zone)).collect();
        let answers = join_all(queries.iter().map(|q| self.resolver.ipv4(q))).await;

        let mut symbols: Vec<Symbol> = Vec::new();
        let mut failed = 0;
        for (zone, answer) in zones.iter().zip(&answers) {
            let codes = match answer {
                Ok(codes) => codes,
                Err(error) if error.is_definite() => continue,
                Err(_) => {
                    failed += 1;
                    continue;
                }
            };
            for code in codes.iter().filter(|c| c.octets()[0] == 127) {
                let last = code.octets()[3];
                for result in zone.results.iter().filter(|r| r.codes.contains(&last)) {
                    match symbols.iter_mut().find(|s| s.name == result.symbol) {
                        Some(existing) if !existing.options.contains(&zone.zone) => {
                            existing.push_option(zone.zone.clone())
                        }
                        Some(_) => {}
                        None => symbols.push(
                            Symbol::new(result.symbol.clone()).with_option(zone.zone.clone()),
                        ),
                    }
                }
            }
        }
        if failed > 0 && failed == zones.len() {
            return Err(CheckError::Temporary("every DNS list failed".into()));
        }
        Ok(symbols)
    }
}

#[cfg(test)]
mod tests {
    use pellet_check::testing::{Fixture, conformance};
    use pellet_dns::{DnsError, testing::FakeResolver};

    use super::*;

    fn name(s: &str) -> SymbolName {
        SymbolName::new(s).unwrap()
    }

    fn zones() -> Vec<DnsblZone> {
        vec![
            DnsblZone {
                zone: "zen.example.org".into(),
                ipv6: true,
                results: vec![
                    DnsblResult {
                        codes: 2..=3,
                        symbol: name("RBL_EXAMPLE_SBL"),
                    },
                    DnsblResult {
                        codes: 4..=7,
                        symbol: name("RBL_EXAMPLE_XBL"),
                    },
                ],
            },
            DnsblZone {
                zone: "bl.example.net".into(),
                ipv6: false,
                results: vec![DnsblResult {
                    codes: 2..=2,
                    symbol: name("RBL_EXAMPLE_SBL"),
                }],
            },
        ]
    }

    fn fixture(ip: &str) -> Fixture {
        let mut fixture = Fixture::default();
        fixture.envelope.client_ip = Some(ip.parse().unwrap());
        fixture
    }

    async fn run(resolver: FakeResolver, fixture: &Fixture) -> Result<Vec<Symbol>, CheckError> {
        DnsblCheck::new(Arc::new(resolver), zones())
            .run(&fixture.context(Stage::Connect))
            .await
    }

    #[tokio::test]
    async fn listed_address_emits_mapped_symbols_with_zones() {
        let resolver = FakeResolver::new()
            .with_ipv4("7.2.0.192.zen.example.org", &["127.0.0.2", "127.0.0.4"])
            .with_ipv4("7.2.0.192.bl.example.net", &["127.0.0.2"]);
        let symbols = run(resolver, &fixture("192.0.2.7")).await.unwrap();
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].name.as_str(), "RBL_EXAMPLE_SBL");
        assert_eq!(symbols[0].options, ["zen.example.org", "bl.example.net"]);
        assert_eq!(symbols[1].name.as_str(), "RBL_EXAMPLE_XBL");
    }

    #[tokio::test]
    async fn unlisted_address_is_clean() {
        assert!(
            run(FakeResolver::new(), &fixture("192.0.2.7"))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn answers_outside_loopback_and_unknown_codes_are_ignored() {
        let resolver = FakeResolver::new()
            .with_ipv4("7.2.0.192.zen.example.org", &["192.0.2.99", "127.0.0.200"]);
        assert!(
            run(resolver, &fixture("192.0.2.7"))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn ipv6_only_asks_zones_that_list_it() {
        let query = list_query("2001:db8::7".parse().unwrap(), "zen.example.org");
        let resolver = FakeResolver::new().with_ipv4(&query, &["127.0.0.2"]);
        let symbols = run(resolver, &fixture("2001:db8::7")).await.unwrap();
        assert_eq!(symbols[0].options, ["zen.example.org"]);
    }

    #[tokio::test]
    async fn mapped_ipv4_is_queried_as_ipv4() {
        let resolver = FakeResolver::new().with_ipv4("7.2.0.192.bl.example.net", &["127.0.0.2"]);
        let symbols = run(resolver, &fixture("::ffff:192.0.2.7")).await.unwrap();
        assert_eq!(symbols[0].options, ["bl.example.net"]);
    }

    #[tokio::test]
    async fn skips_local_addresses_and_authenticated_clients() {
        let resolver = FakeResolver::new();
        assert!(
            run(FakeResolver::new(), &fixture("10.0.0.5"))
                .await
                .unwrap()
                .is_empty()
        );
        let mut authenticated = fixture("192.0.2.7");
        authenticated.envelope.authenticated = true;
        let check = DnsblCheck::new(Arc::new(resolver), zones());
        assert!(
            check
                .run(&authenticated.context(Stage::Connect))
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            check
                .run(&Fixture::default().context(Stage::Connect))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn partial_failures_are_left_out_and_total_failure_is_temporary() {
        let partial = FakeResolver::new()
            .with_error("7.2.0.192.zen.example.org", DnsError::Timeout)
            .with_ipv4("7.2.0.192.bl.example.net", &["127.0.0.2"]);
        assert_eq!(run(partial, &fixture("192.0.2.7")).await.unwrap().len(), 1);

        let total = FakeResolver::new()
            .with_error("7.2.0.192.zen.example.org", DnsError::Timeout)
            .with_error(
                "7.2.0.192.bl.example.net",
                DnsError::Failed("servfail".into()),
            );
        assert!(matches!(
            run(total, &fixture("192.0.2.7")).await,
            Err(CheckError::Temporary(_))
        ));
    }

    #[tokio::test]
    async fn passes_conformance() {
        let resolver = FakeResolver::new()
            .with_ipv4("7.2.0.192.zen.example.org", &["127.0.0.2", "127.0.0.5"])
            .with_ipv4("7.2.0.192.bl.example.net", &["127.0.0.2"]);
        let check = DnsblCheck::new(Arc::new(resolver), zones());
        assert_eq!(check.symbols().len(), 2);
        conformance(
            &check,
            &[
                fixture("192.0.2.7"),
                fixture("198.51.100.1"),
                Fixture::default(),
            ],
        )
        .await;
    }
}
