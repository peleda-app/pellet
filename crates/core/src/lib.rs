//! Envelope, message, symbols, scores and verdicts shared by every Pellet module.
//!
//! Everything here is plain data: no I/O and no network. The serialized form of [`Verdict`] is
//! what the HTTP API and the command line print, so it is part of the public contract.

mod envelope;
mod error;
mod message;
mod score;
mod stage;
mod symbol;
mod verdict;

pub use envelope::Envelope;
pub use error::CoreError;
pub use message::{Header, Message};
pub use score::{Action, ScoreTable, Thresholds};
pub use stage::Stage;
pub use symbol::{MAX_OPTION_LEN, MAX_OPTIONS, MAX_SYMBOL_LEN, Symbol, SymbolName};
pub use verdict::{Failure, FailureReason, ScoredSymbol, Verdict};
