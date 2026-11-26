use async_trait::async_trait;
use pellet_check::{Check, CheckError, Context};
use pellet_core::{Stage, Symbol, SymbolName};

use crate::mail::{Mail, Symbols};

/// The decoded subject, at [`Stage::Data`].
///
/// | Symbol | When |
/// | --- | --- |
/// | `SUBJ_ALL_CAPS` | at least two words and ten letters, all of them capitals |
/// | `SUBJECT_ENDS_SPACES` | trailing whitespace |
/// | `SUBJECT_HAS_CURRENCY` | a currency sign |
pub struct SubjectCheck {
    symbols: Symbols,
}

impl SubjectCheck {
    /// The check.
    pub fn new() -> Self {
        SubjectCheck {
            symbols: Symbols::new(&[
                "SUBJ_ALL_CAPS",
                "SUBJECT_ENDS_SPACES",
                "SUBJECT_HAS_CURRENCY",
            ]),
        }
    }
}

impl Default for SubjectCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Check for SubjectCheck {
    fn name(&self) -> &str {
        "content.subject"
    }

    fn stage(&self) -> Stage {
        Stage::Data
    }

    fn symbols(&self) -> &[SymbolName] {
        self.symbols.all()
    }

    async fn run(&self, ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError> {
        let message = ctx
            .message
            .ok_or_else(|| CheckError::Failed("no message at the data stage".into()))?;
        let Some(subject) = Mail::parse(message).subject else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        let letters: Vec<char> = subject.chars().filter(|c| c.is_alphabetic()).collect();
        let words = subject
            .split_whitespace()
            .filter(|w| w.chars().any(char::is_alphabetic))
            .count();
        if words >= 2 && letters.len() >= 10 && letters.iter().all(|c| c.is_uppercase()) {
            out.push(self.symbols.get("SUBJ_ALL_CAPS"));
        }
        if subject.ends_with(char::is_whitespace) {
            out.push(self.symbols.get("SUBJECT_ENDS_SPACES"));
        }
        if subject
            .chars()
            .any(|c| matches!(c, '$' | '€' | '£' | '¥' | '₽' | '₹' | '₿' | '₩'))
        {
            out.push(self.symbols.get("SUBJECT_HAS_CURRENCY"));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use pellet_check::testing::{Fixture, conformance};

    use super::*;

    async fn of(subject: &str) -> Vec<String> {
        let fixture = Fixture::message(&format!("Subject: {subject}\r\n\r\nb"));
        SubjectCheck::new()
            .run(&fixture.context(Stage::Data))
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.name.to_string())
            .collect()
    }

    #[tokio::test]
    async fn shapes() {
        assert_eq!(of("FREE MONEY INSIDE").await, ["SUBJ_ALL_CAPS"]);
        assert!(of("ASAP").await.is_empty(), "one short word");
        assert!(of("Lunch at noon").await.is_empty());
        assert_eq!(of("Win €500 today").await, ["SUBJECT_HAS_CURRENCY"]);
        assert_eq!(of("=?utf-8?q?Hello=20?=").await, ["SUBJECT_ENDS_SPACES"]);
    }

    #[tokio::test]
    async fn passes_conformance() {
        conformance(
            &SubjectCheck::new(),
            &[
                Fixture::message("Subject: FREE MONEY $$$ \r\n\r\n"),
                Fixture::message(""),
            ],
        )
        .await;
    }
}
