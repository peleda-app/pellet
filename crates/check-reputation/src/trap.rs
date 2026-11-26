use std::collections::HashSet;

use async_trait::async_trait;
use pellet_check::{Check, CheckError, Context, symbol_names};
use pellet_core::{Stage, Symbol, SymbolName};

/// Mail to addresses nobody uses, published only where harvesters find them, at
/// [`Stage::Data`].
///
/// | Symbol | When |
/// | --- | --- |
/// | `SPAM_TRAP` | an envelope recipient is a trap address, or its domain is a trap domain |
///
/// Traps are compared without case. An entry `@trap.example.org` makes every address of that
/// domain a trap. The symbol carries no option, so the trap addresses never leave the check.
/// Classifier and reputation treat `SPAM_TRAP` as a strong spam signal.
pub struct TrapCheck {
    addresses: HashSet<String>,
    domains: HashSet<String>,
    declared: Vec<SymbolName>,
}

impl TrapCheck {
    /// The check over trap addresses and `@domain` entries.
    pub fn new<S: AsRef<str>>(traps: impl IntoIterator<Item = S>) -> Self {
        let mut addresses = HashSet::new();
        let mut domains = HashSet::new();
        for trap in traps {
            let trap = trap.as_ref().trim().to_lowercase();
            match trap.strip_prefix('@') {
                Some(domain) if !domain.is_empty() => {
                    domains.insert(domain.to_string());
                }
                Some(_) => {}
                None if !trap.is_empty() => {
                    addresses.insert(trap);
                }
                None => {}
            }
        }
        TrapCheck {
            addresses,
            domains,
            declared: symbol_names(&["SPAM_TRAP"]),
        }
    }

    fn is_trap(&self, recipient: &str) -> bool {
        let recipient = recipient
            .trim()
            .trim_start_matches('<')
            .trim_end_matches('>')
            .to_lowercase();
        self.addresses.contains(&recipient)
            || recipient
                .rsplit_once('@')
                .is_some_and(|(_, domain)| self.domains.contains(domain))
    }
}

#[async_trait]
impl Check for TrapCheck {
    fn name(&self) -> &str {
        "trap"
    }

    fn stage(&self) -> Stage {
        Stage::Data
    }

    fn symbols(&self) -> &[SymbolName] {
        &self.declared
    }

    async fn run(&self, ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError> {
        let hit = ctx.envelope.recipients.iter().any(|r| self.is_trap(r));
        Ok(hit
            .then(|| Symbol::new(self.declared[0].clone()))
            .into_iter()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use pellet_check::testing::{Fixture, conformance};

    use super::*;

    fn fixture(recipients: &[&str]) -> Fixture {
        let mut fixture = Fixture::message("From: ana@example.com\r\n\r\nb");
        fixture.envelope.recipients = recipients.iter().map(|r| r.to_string()).collect();
        fixture
    }

    async fn names(check: &TrapCheck, recipients: &[&str]) -> Vec<String> {
        check
            .run(&fixture(recipients).context(Stage::Data))
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.name.to_string())
            .collect()
    }

    #[tokio::test]
    async fn traps_by_address_and_domain() {
        let check = TrapCheck::new(["Trap@Example.org", "@bait.example.net", "", "@"]);
        assert_eq!(
            names(&check, &["bo@example.org", "<trap@example.org>"]).await,
            ["SPAM_TRAP"]
        );
        assert_eq!(
            names(&check, &["anyone@BAIT.example.net"]).await,
            ["SPAM_TRAP"]
        );
        assert!(names(&check, &["bo@example.org"]).await.is_empty());
        assert!(names(&check, &["x@sub.bait.example.net"]).await.is_empty());
        let symbols = check
            .run(&fixture(&["trap@example.org"]).context(Stage::Data))
            .await
            .unwrap();
        assert!(
            symbols[0].options.is_empty(),
            "trap addresses stay inside the check"
        );
    }

    #[tokio::test]
    async fn passes_conformance() {
        let check = TrapCheck::new(["trap@example.org"]);
        conformance(&check, &[fixture(&["trap@example.org"]), fixture(&[])]).await;
    }
}
