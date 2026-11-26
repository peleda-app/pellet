//! Tokenizers, feature hashing and an online logistic classifier with a fixed memory budget.
//!
//! No I/O: a [`Model`] turns into bytes and back, and the host decides where those live.

mod model;
mod tokens;

pub use model::{MAX_BITS, MIN_BITS, Model, ModelError, Params};
pub use tokens::{Document, MAX_TOKENS, TOKENIZER_VERSION, tokens};
