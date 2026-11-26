use serde::{Deserialize, Serialize};

use crate::{Action, Stage, SymbolName};

/// A symbol with the score it contributed and the stage that produced it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoredSymbol {
    /// The symbol's name.
    pub name: SymbolName,
    /// Its score from the score table, `0.0` when unknown.
    pub score: f64,
    /// The stage whose checks emitted it.
    pub stage: Stage,
    /// What triggered it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
}

/// Why a check contributed nothing, or less than it tried to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "detail")]
pub enum FailureReason {
    /// The check did not finish before the stage deadline.
    Deadline,
    /// The check returned an error; the detail never holds message content.
    Error(String),
    /// The check emitted a symbol it had not declared; the symbol was dropped.
    Undeclared(SymbolName),
}

/// A check that failed during a stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    /// The check's name.
    pub check: String,
    /// The stage it ran in.
    pub stage: Stage,
    /// What went wrong.
    pub reason: FailureReason,
}

/// The result after a stage: every symbol so far, their total and the action it maps to.
///
/// Symbols are sorted by score, highest first, then by name, and each name appears once.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    /// The last stage that ran.
    pub stage: Stage,
    /// Sum of the scores of every symbol.
    pub score: f64,
    /// The action for that score.
    pub action: Action,
    /// Every symbol from every stage so far.
    pub symbols: Vec<ScoredSymbol>,
    /// Checks that failed, in the order they were seen.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<Failure>,
}

impl Verdict {
    /// The symbol with this name, if it fired.
    pub fn symbol(&self, name: &str) -> Option<&ScoredSymbol> {
        self.symbols.iter().find(|s| s.name.as_str() == name)
    }

    /// Whether a symbol with this name fired.
    pub fn has(&self, name: &str) -> bool {
        self.symbol(name).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_for_output() {
        let verdict = Verdict {
            stage: Stage::Data,
            score: 2.0,
            action: Action::Accept,
            symbols: vec![ScoredSymbol {
                name: SymbolName::new("MISSING_DATE").unwrap(),
                score: 2.0,
                stage: Stage::Data,
                options: vec![],
            }],
            failures: vec![Failure {
                check: "slow".into(),
                stage: Stage::Data,
                reason: FailureReason::Deadline,
            }],
        };
        let json = serde_json::to_value(&verdict).unwrap();
        assert_eq!(json["action"], "accept");
        assert_eq!(json["symbols"][0]["name"], "MISSING_DATE");
        assert!(json["symbols"][0].get("options").is_none());
        assert_eq!(json["failures"][0]["reason"]["kind"], "deadline");
        let back: Verdict = serde_json::from_value(json).unwrap();
        assert_eq!(back, verdict);
        assert!(back.has("MISSING_DATE"));
        assert!(!back.has("OTHER"));
    }
}
