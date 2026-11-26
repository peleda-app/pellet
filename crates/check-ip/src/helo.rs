use std::{net::IpAddr, sync::Arc};

use async_trait::async_trait;
use pellet_check::{Check, CheckError, Context, symbol_names};
use pellet_core::{Stage, Symbol, SymbolName};
use pellet_dns::{DnsError, Resolver, normalize};

use crate::{emit, is_listable};

/// The HELO/EHLO name at [`Stage::Helo`].
///
/// | Symbol | When |
/// | --- | --- |
/// | `HELO_BAREIP` | the name is an address, bare or as an `[address literal]` |
/// | `HELO_NOT_FQDN` | the name has no dot or is not a valid DNS name |
/// | `HELO_NORES_A_OR_MX` | the name has no A, AAAA or MX record (definite answers only) |
/// | `HELO_IPREV_MISMATCH` | the client's PTR names exist and none equals the HELO name |
///
/// Skipped for authenticated clients. The PTR names come from `client_ptr` when the host set
/// it, otherwise from a lookup.
pub struct HeloCheck {
    resolver: Arc<dyn Resolver>,
    declared: Vec<SymbolName>,
}

impl HeloCheck {
    /// Builds the check.
    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        HeloCheck {
            resolver,
            declared: symbol_names(&[
                "HELO_BAREIP",
                "HELO_NOT_FQDN",
                "HELO_NORES_A_OR_MX",
                "HELO_IPREV_MISMATCH",
            ]),
        }
    }

    async fn resolves(&self, name: &str) -> bool {
        let (v4, v6, mx) = futures::join!(
            self.resolver.ipv4(name),
            self.resolver.ipv6(name),
            self.resolver.mx(name)
        );
        let missing = [v4.err(), v6.err(), mx.err()];
        !missing.iter().all(|e| e == &Some(DnsError::NotFound))
    }

    async fn ptr_names(&self, ctx: &Context<'_>) -> Vec<String> {
        if let Some(ptr) = &ctx.envelope.client_ptr {
            return normalize(ptr).into_iter().collect();
        }
        match ctx.envelope.client_ip {
            Some(ip) if is_listable(ip) => self.resolver.ptr(ip).await.unwrap_or_default(),
            _ => Vec::new(),
        }
    }
}

fn address_literal(helo: &str) -> bool {
    let inner = helo
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .map(|h| h.strip_prefix("IPv6:").unwrap_or(h));
    inner.unwrap_or(helo).parse::<IpAddr>().is_ok()
}

#[async_trait]
impl Check for HeloCheck {
    fn name(&self) -> &str {
        "ip.helo"
    }

    fn stage(&self) -> Stage {
        Stage::Helo
    }

    fn symbols(&self) -> &[SymbolName] {
        &self.declared
    }

    async fn run(&self, ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError> {
        let Some(helo) = ctx.envelope.helo.as_deref().map(str::trim) else {
            return Ok(Vec::new());
        };
        if ctx.envelope.authenticated || helo.is_empty() {
            return Ok(Vec::new());
        }
        if address_literal(helo) {
            return Ok(vec![emit(&self.declared, "HELO_BAREIP")]);
        }
        let name = match normalize(helo) {
            Ok(name) if name.contains('.') => name,
            _ => return Ok(vec![emit(&self.declared, "HELO_NOT_FQDN")]),
        };

        let mut out = Vec::new();
        let (resolves, ptr) = futures::join!(self.resolves(&name), self.ptr_names(ctx));
        if !resolves {
            out.push(emit(&self.declared, "HELO_NORES_A_OR_MX"));
        }
        if !ptr.is_empty() && !ptr.contains(&name) {
            out.push(emit(&self.declared, "HELO_IPREV_MISMATCH"));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use pellet_check::testing::{Fixture, conformance};
    use pellet_dns::testing::FakeResolver;

    use super::*;

    fn fixture(helo: &str) -> Fixture {
        let mut fixture = Fixture::default();
        fixture.envelope.client_ip = Some("192.0.2.7".parse().unwrap());
        fixture.envelope.helo = Some(helo.into());
        fixture
    }

    fn resolver() -> FakeResolver {
        FakeResolver::new()
            .with_ipv4("mail.example.org", &["192.0.2.7"])
            .with_mx("example.net", &[(10, "mx.example.net")])
            .with_ptr("192.0.2.7", &["mail.example.org"])
    }

    async fn names(resolver: FakeResolver, fixture: &Fixture) -> Vec<String> {
        HeloCheck::new(Arc::new(resolver))
            .run(&fixture.context(Stage::Helo))
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.name.to_string())
            .collect()
    }

    #[tokio::test]
    async fn matching_resolvable_name_is_clean() {
        assert!(
            names(resolver(), &fixture("Mail.Example.org"))
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn address_literals() {
        for helo in ["192.0.2.7", "[192.0.2.7]", "[IPv6:2001:db8::1]"] {
            assert_eq!(
                names(resolver(), &fixture(helo)).await,
                ["HELO_BAREIP"],
                "{helo}"
            );
        }
    }

    #[tokio::test]
    async fn names_without_dots_or_invalid() {
        for helo in ["localhost", "my_pc!", "-bad.example"] {
            assert_eq!(
                names(resolver(), &fixture(helo)).await,
                ["HELO_NOT_FQDN"],
                "{helo}"
            );
        }
    }

    #[tokio::test]
    async fn unresolvable_and_mismatching() {
        assert_eq!(
            names(resolver(), &fixture("ghost.example.com")).await,
            ["HELO_NORES_A_OR_MX", "HELO_IPREV_MISMATCH"]
        );
        assert_eq!(
            names(resolver(), &fixture("example.net")).await,
            ["HELO_IPREV_MISMATCH"],
            "an MX record is enough to resolve"
        );
    }

    #[tokio::test]
    async fn dns_failures_do_not_count_as_missing() {
        let failing = resolver().with_error("slow.example.com", DnsError::Timeout);
        assert_eq!(
            names(failing, &fixture("slow.example.com")).await,
            ["HELO_IPREV_MISMATCH"]
        );
    }

    #[tokio::test]
    async fn uses_host_supplied_ptr_and_no_ptr_means_no_mismatch() {
        let mut supplied = fixture("mail.example.org");
        supplied.envelope.client_ptr = Some("other.example.org".into());
        assert_eq!(names(resolver(), &supplied).await, ["HELO_IPREV_MISMATCH"]);

        let no_ptr = FakeResolver::new().with_ipv4("mail.example.org", &["192.0.2.7"]);
        assert!(names(no_ptr, &fixture("mail.example.org")).await.is_empty());
    }

    #[tokio::test]
    async fn skips_authenticated_and_missing_helo() {
        let mut authenticated = fixture("localhost");
        authenticated.envelope.authenticated = true;
        assert!(names(resolver(), &authenticated).await.is_empty());
        assert!(names(resolver(), &Fixture::default()).await.is_empty());
    }

    #[tokio::test]
    async fn passes_conformance() {
        conformance(
            &HeloCheck::new(Arc::new(resolver())),
            &[
                fixture("mail.example.org"),
                fixture("[192.0.2.7]"),
                fixture("localhost"),
                fixture("ghost.example.com"),
                Fixture::default(),
            ],
        )
        .await;
    }
}
