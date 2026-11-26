use std::sync::Arc;

use async_trait::async_trait;
use pellet_check::{Check, CheckError, Context, symbol_names};
use pellet_core::{Message, Stage, Symbol, SymbolName};
use pellet_dns::{DnsError, Resolver, normalize};

use crate::emit;

/// Whether the From domain can receive mail, at [`Stage::Data`].
///
/// | Symbol | When |
/// | --- | --- |
/// | `FROMHOST_NORES_A_OR_MX` | the domain of the first From address has no A, AAAA or MX record (definite answers only) |
///
/// Skipped for authenticated clients and when From holds no domain.
pub struct FromHostCheck {
    resolver: Arc<dyn Resolver>,
    declared: Vec<SymbolName>,
}

impl FromHostCheck {
    /// Builds the check.
    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        FromHostCheck {
            resolver,
            declared: symbol_names(&["FROMHOST_NORES_A_OR_MX"]),
        }
    }
}

/// The domain after the last `@` of the From field, up to `>`, whitespace or a comma.
fn from_domain(message: &Message) -> Option<String> {
    let value = message.header("from")?.value_str().into_owned();
    let (_, after) = value.rsplit_once('@')?;
    let domain: String = after
        .chars()
        .take_while(|c| !c.is_whitespace() && !matches!(c, '>' | ',' | ')' | '"'))
        .collect();
    normalize(&domain).ok().filter(|d| d.contains('.'))
}

#[async_trait]
impl Check for FromHostCheck {
    fn name(&self) -> &str {
        "ip.from_host"
    }

    fn stage(&self) -> Stage {
        Stage::Data
    }

    fn symbols(&self) -> &[SymbolName] {
        &self.declared
    }

    async fn run(&self, ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError> {
        if ctx.envelope.authenticated {
            return Ok(Vec::new());
        }
        let message = ctx
            .message
            .ok_or_else(|| CheckError::Failed("no message at the data stage".into()))?;
        let Some(domain) = from_domain(message) else {
            return Ok(Vec::new());
        };
        let (v4, v6, mx) = futures::join!(
            self.resolver.ipv4(&domain),
            self.resolver.ipv6(&domain),
            self.resolver.mx(&domain)
        );
        let missing = [v4.err(), v6.err(), mx.err()];
        Ok(if missing.iter().all(|e| e == &Some(DnsError::NotFound)) {
            vec![emit(&self.declared, "FROMHOST_NORES_A_OR_MX")]
        } else {
            Vec::new()
        })
    }
}

#[cfg(test)]
mod tests {
    use pellet_check::testing::{Fixture, conformance};
    use pellet_dns::testing::FakeResolver;

    use super::*;

    async fn names(resolver: FakeResolver, from: &str) -> Vec<String> {
        let fixture = Fixture::message(&format!("From: {from}\r\n\r\nb"));
        FromHostCheck::new(Arc::new(resolver))
            .run(&fixture.context(Stage::Data))
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.name.to_string())
            .collect()
    }

    #[tokio::test]
    async fn sender_domains() {
        let resolver = || {
            FakeResolver::new()
                .with_mx("example.com", &[(10, "mx.example.com")])
                .with_error("slow.example.net", DnsError::Timeout)
        };
        assert!(names(resolver(), "Ana <ana@Example.COM>").await.is_empty());
        assert_eq!(
            names(resolver(), "ghost@nowhere.example").await,
            ["FROMHOST_NORES_A_OR_MX"]
        );
        assert!(
            names(resolver(), "x@slow.example.net").await.is_empty(),
            "timeouts do not count"
        );
        assert!(names(resolver(), "no domain").await.is_empty());
    }

    #[tokio::test]
    async fn passes_conformance() {
        conformance(
            &FromHostCheck::new(Arc::new(FakeResolver::new())),
            &[
                Fixture::message("From: a@nowhere.example\r\n\r\n"),
                Fixture::message(""),
            ],
        )
        .await;
    }
}
