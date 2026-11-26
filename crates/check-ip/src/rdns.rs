use std::sync::Arc;

use async_trait::async_trait;
use pellet_check::{Check, CheckError, Context, symbol_names};
use pellet_core::{Stage, Symbol, SymbolName};
use pellet_dns::{DnsError, Resolver};

use crate::{emit, is_listable};

/// Reverse DNS of the client at [`Stage::Connect`].
///
/// | Symbol | When |
/// | --- | --- |
/// | `RDNS_NONE` | the address has no PTR record |
/// | `RDNS_DNSFAIL` | the PTR lookup timed out or failed |
///
/// When the host already put a confirmed name in `client_ptr`, nothing is looked up.
pub struct ReverseDnsCheck {
    resolver: Arc<dyn Resolver>,
    declared: Vec<SymbolName>,
}

impl ReverseDnsCheck {
    /// Builds the check.
    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        ReverseDnsCheck {
            resolver,
            declared: symbol_names(&["RDNS_NONE", "RDNS_DNSFAIL"]),
        }
    }
}

#[async_trait]
impl Check for ReverseDnsCheck {
    fn name(&self) -> &str {
        "ip.rdns"
    }

    fn stage(&self) -> Stage {
        Stage::Connect
    }

    fn symbols(&self) -> &[SymbolName] {
        &self.declared
    }

    async fn run(&self, ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError> {
        let envelope = ctx.envelope;
        let Some(ip) = envelope.client_ip else {
            return Ok(Vec::new());
        };
        if envelope.authenticated || envelope.client_ptr.is_some() || !is_listable(ip) {
            return Ok(Vec::new());
        }
        Ok(match self.resolver.ptr(ip).await {
            Ok(_) => Vec::new(),
            Err(DnsError::NotFound | DnsError::InvalidName) => {
                vec![emit(&self.declared, "RDNS_NONE")]
            }
            Err(DnsError::Timeout | DnsError::Failed(_)) => {
                vec![emit(&self.declared, "RDNS_DNSFAIL")]
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use pellet_check::testing::{Fixture, conformance};
    use pellet_dns::testing::FakeResolver;

    use super::*;

    fn fixture(ip: &str) -> Fixture {
        let mut fixture = Fixture::default();
        fixture.envelope.client_ip = Some(ip.parse().unwrap());
        fixture
    }

    async fn names(resolver: FakeResolver, fixture: &Fixture) -> Vec<String> {
        ReverseDnsCheck::new(Arc::new(resolver))
            .run(&fixture.context(Stage::Connect))
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.name.to_string())
            .collect()
    }

    #[tokio::test]
    async fn present_ptr_is_clean() {
        let resolver = FakeResolver::new().with_ptr("192.0.2.7", &["mail.example.org"]);
        assert!(names(resolver, &fixture("192.0.2.7")).await.is_empty());
    }

    #[tokio::test]
    async fn missing_ptr_and_failures() {
        assert_eq!(
            names(FakeResolver::new(), &fixture("192.0.2.7")).await,
            ["RDNS_NONE"]
        );
        let failing = FakeResolver::new().with_error("192.0.2.7", DnsError::Timeout);
        assert_eq!(
            names(failing, &fixture("192.0.2.7")).await,
            ["RDNS_DNSFAIL"]
        );
    }

    #[tokio::test]
    async fn trusts_the_host_and_skips_local_or_authenticated() {
        let resolver = Arc::new(FakeResolver::new());
        let check = ReverseDnsCheck::new(resolver.clone());
        let mut confirmed = fixture("192.0.2.7");
        confirmed.envelope.client_ptr = Some("mail.example.org".into());
        assert!(
            check
                .run(&confirmed.context(Stage::Connect))
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            check
                .run(&fixture("192.168.0.4").context(Stage::Connect))
                .await
                .unwrap()
                .is_empty()
        );
        let mut authenticated = fixture("192.0.2.7");
        authenticated.envelope.authenticated = true;
        assert!(
            check
                .run(&authenticated.context(Stage::Connect))
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(resolver.queries(), 0);
    }

    #[tokio::test]
    async fn passes_conformance() {
        let resolver = FakeResolver::new().with_ptr("192.0.2.7", &["mail.example.org"]);
        conformance(
            &ReverseDnsCheck::new(Arc::new(resolver)),
            &[
                fixture("192.0.2.7"),
                fixture("198.51.100.1"),
                Fixture::default(),
            ],
        )
        .await;
    }
}
