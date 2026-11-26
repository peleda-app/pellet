//! Fakes and the conformance suite for the `Check` contract.
//!
//! An implementation proves it keeps the contract by running the suite over contexts that make it
//! emit symbols and contexts that do not:
//!
//! ```ignore
//! #[tokio::test]
//! async fn conformance() {
//!     let fixtures = [Fixture::message("From: a@example.com\r\n\r\n")];
//!     pellet_check::testing::conformance(&MyCheck::new(), &fixtures).await;
//! }
//! ```

use std::{collections::HashSet, time::Duration};

use async_trait::async_trait;
use pellet_core::{Envelope, Message, Stage, Symbol, SymbolName};

use crate::{Check, CheckError, Context, symbol_names};

/// Owned inputs for building a [`Context`] in tests.
#[derive(Debug, Clone, Default)]
pub struct Fixture {
    /// The envelope.
    pub envelope: Envelope,
    /// The message, used at [`Stage::Data`] only.
    pub message: Option<Message>,
    /// Symbols from earlier stages.
    pub earlier: Vec<Symbol>,
}

impl Fixture {
    /// A fixture with this message and an empty envelope.
    pub fn message(raw: &str) -> Self {
        Fixture {
            message: Some(Message::new(raw.as_bytes())),
            ..Fixture::default()
        }
    }

    /// The context a check at `stage` would see. At [`Stage::Data`] a missing message is empty.
    pub fn context(&self, stage: Stage) -> Context<'_> {
        static EMPTY: std::sync::OnceLock<Message> = std::sync::OnceLock::new();
        let message = match stage {
            Stage::Data => Some(
                self.message
                    .as_ref()
                    .unwrap_or_else(|| EMPTY.get_or_init(|| Message::new(Vec::new()))),
            ),
            _ => None,
        };
        Context {
            stage,
            envelope: &self.envelope,
            message,
            earlier: &self.earlier,
        }
    }
}

/// Runs `check` over every fixture at its stage and asserts the contract: a non-empty name,
/// unique declared symbols, only declared symbols emitted, no name twice, and the same output on
/// a second run.
pub async fn conformance(check: &dyn Check, fixtures: &[Fixture]) {
    assert!(!check.name().is_empty(), "check name is empty");
    let declared: HashSet<&SymbolName> = check.symbols().iter().collect();
    assert_eq!(
        declared.len(),
        check.symbols().len(),
        "{}: declared symbols repeat",
        check.name()
    );

    for (i, fixture) in fixtures.iter().enumerate() {
        let ctx = fixture.context(check.stage());
        let first = check.run(&ctx).await;
        let second = check.run(&ctx).await;
        assert_eq!(
            first,
            second,
            "{}: fixture {i} is not deterministic",
            check.name()
        );
        let Ok(symbols) = first else { continue };
        let mut seen = HashSet::new();
        for symbol in &symbols {
            assert!(
                declared.contains(&symbol.name),
                "{}: fixture {i} emitted undeclared {}",
                check.name(),
                symbol.name
            );
            assert!(
                seen.insert(&symbol.name),
                "{}: fixture {i} emitted {} twice",
                check.name(),
                symbol.name
            );
        }
    }
}

/// A check that always emits the same symbols.
pub struct FixedCheck {
    name: String,
    stage: Stage,
    declared: Vec<SymbolName>,
    emits: Vec<Symbol>,
}

impl FixedCheck {
    /// Declares and emits `symbols` at `stage`.
    pub fn new(name: &str, stage: Stage, symbols: &[&str]) -> Self {
        let declared = symbol_names(symbols);
        FixedCheck {
            name: name.into(),
            stage,
            emits: declared.iter().cloned().map(Symbol::new).collect(),
            declared,
        }
    }

    /// Declares `declared` but emits `emits`, to exercise the engine's guards.
    pub fn lying(name: &str, stage: Stage, declared: &[&str], emits: &[&str]) -> Self {
        FixedCheck {
            name: name.into(),
            stage,
            declared: symbol_names(declared),
            emits: symbol_names(emits).into_iter().map(Symbol::new).collect(),
        }
    }
}

#[async_trait]
impl Check for FixedCheck {
    fn name(&self) -> &str {
        &self.name
    }

    fn stage(&self) -> Stage {
        self.stage
    }

    fn symbols(&self) -> &[SymbolName] {
        &self.declared
    }

    async fn run(&self, _ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError> {
        Ok(self.emits.clone())
    }
}

/// A check that always fails with [`CheckError::Temporary`].
pub struct FailingCheck {
    name: String,
    stage: Stage,
}

impl FailingCheck {
    /// A failing check at `stage`.
    pub fn new(name: &str, stage: Stage) -> Self {
        FailingCheck {
            name: name.into(),
            stage,
        }
    }
}

#[async_trait]
impl Check for FailingCheck {
    fn name(&self) -> &str {
        &self.name
    }

    fn stage(&self) -> Stage {
        self.stage
    }

    fn symbols(&self) -> &[SymbolName] {
        &[]
    }

    async fn run(&self, _ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError> {
        Err(CheckError::Temporary("unavailable".into()))
    }
}

/// A check that sleeps on the Tokio clock before emitting its symbols.
pub struct SlowCheck {
    inner: FixedCheck,
    delay: Duration,
}

impl SlowCheck {
    /// Emits `symbols` at `stage` after `delay`.
    pub fn new(name: &str, stage: Stage, symbols: &[&str], delay: Duration) -> Self {
        SlowCheck {
            inner: FixedCheck::new(name, stage, symbols),
            delay,
        }
    }
}

#[async_trait]
impl Check for SlowCheck {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn stage(&self) -> Stage {
        self.inner.stage()
    }

    fn symbols(&self) -> &[SymbolName] {
        self.inner.symbols()
    }

    async fn run(&self, ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError> {
        tokio::time::sleep(self.delay).await;
        self.inner.run(ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fakes_pass_conformance() {
        let fixtures = [
            Fixture::default(),
            Fixture::message("To: a@example.org\r\n\r\n"),
        ];
        conformance(
            &FixedCheck::new("fixed", Stage::Data, &["A", "B"]),
            &fixtures,
        )
        .await;
        conformance(&FailingCheck::new("failing", Stage::Connect), &fixtures).await;
    }

    #[tokio::test]
    #[should_panic(expected = "undeclared")]
    async fn conformance_catches_undeclared_symbols() {
        let check = FixedCheck::lying("liar", Stage::Data, &["A"], &["B"]);
        conformance(&check, &[Fixture::default()]).await;
    }

    #[test]
    fn fixture_gives_a_message_only_at_data() {
        let fixture = Fixture::message("Subject: x\r\n\r\n");
        assert!(fixture.context(Stage::Rcpt).message.is_none());
        assert!(fixture.context(Stage::Data).message.is_some());
        assert!(
            Fixture::default()
                .context(Stage::Data)
                .message
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn earlier_has_matches_names() {
        let fixture = Fixture {
            earlier: vec![Symbol::new(SymbolName::new("RBL_HIT").unwrap())],
            ..Fixture::default()
        };
        let ctx = fixture.context(Stage::Data);
        assert!(ctx.earlier_has("RBL_HIT"));
        assert!(!ctx.earlier_has("OTHER"));
    }
}
