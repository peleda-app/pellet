//! Rule, score and list data, its loader and the expression language that evaluates it.
//!
//! Nothing here does I/O at run time: the bundled data is compiled in, and evaluation only reads
//! the [`Env`] it is given.

mod condition;
mod data;
mod expr;
mod functions;
mod value;

pub use condition::{Condition, ConditionError};
pub use data::{
    DataError, DnsblRule, Fingerprints, HttpList, ListFormat, Lists, MESSAGE_VARIABLES,
    RemoteLists, Rule, RuleSet, Scope, fingerprint,
};
pub use expr::{Env, Expr, ParseError};
pub use functions::FUNCTIONS;
pub use value::Value;
