//! Check contract: one piece of analysis that reads the message context and emits symbols.
//!
//! A check receives everything else it needs (a resolver, state, data) when the composition root
//! builds it, so this contract only carries the SMTP context.

use async_trait::async_trait;
use pellet_core::{Envelope, Message, Stage, Symbol, SymbolName};

#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// What a check sees when it runs.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    /// The stage being run; always the check's own stage.
    pub stage: Stage,
    /// The envelope as known at this stage.
    pub envelope: &'a Envelope,
    /// The message; always `Some` at [`Stage::Data`] and `None` before it.
    pub message: Option<&'a Message>,
    /// Symbols emitted so far, without scores: by earlier stages, and for a late check also by
    /// the other checks of this stage.
    pub earlier: &'a [Symbol],
}

impl Context<'_> {
    /// Whether an earlier stage emitted a symbol with this name.
    pub fn earlier_has(&self, name: &str) -> bool {
        self.earlier.iter().any(|s| s.name.as_str() == name)
    }
}

/// Why a check could not finish. The text never holds message content or secrets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckError {
    /// A dependency was unavailable or slow (DNS, state); the same input may succeed later.
    #[error("temporary failure: {0}")]
    Temporary(String),
    /// The check cannot handle this input or is misconfigured.
    #[error("check failed: {0}")]
    Failed(String),
}

/// One piece of analysis.
///
/// Guarantees an implementation must keep:
/// - [`Check::name`] and [`Check::symbols`] never change for the life of the value.
/// - [`Check::run`] returns only symbols listed in [`Check::symbols`], each name at most once.
/// - The same context gives the same symbols, as long as the check's outside data (DNS answers,
///   state, lists) is unchanged.
/// - Errors never stop the verdict: the engine records them and carries on without the check.
/// - `run` may be called concurrently for different messages.
#[async_trait]
pub trait Check: Send + Sync {
    /// A unique, stable name such as `content.headers`, used in failures and logs.
    fn name(&self) -> &str;

    /// The stage at which the engine runs this check.
    fn stage(&self) -> Stage;

    /// Every symbol this check can emit.
    fn symbols(&self) -> &[SymbolName];

    /// Whether the check runs after the other checks of its stage and sees their symbols, as
    /// rules and composites must. Late checks of one stage run concurrently with each other.
    fn late(&self) -> bool {
        false
    }

    /// Analyzes the context and returns the symbols that apply.
    async fn run(&self, ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError>;
}

/// Parses a list of symbol names for [`Check::symbols`].
///
/// # Panics
///
/// Panics on an invalid name; meant for names written in code.
pub fn symbol_names(names: &[&str]) -> Vec<SymbolName> {
    names
        .iter()
        .map(|n| SymbolName::new(n).unwrap_or_else(|e| panic!("{e}")))
        .collect()
}
