/// Invalid plain data handed to a `pellet-core` constructor.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum CoreError {
    /// A symbol name is empty, too long, or not made of `A-Z`, `0-9` and `_` starting with a letter.
    #[error("invalid symbol name {0:?}")]
    InvalidSymbolName(String),
    /// A score or threshold is NaN or infinite.
    #[error("score for {0} is not a finite number")]
    NonFiniteScore(String),
}
