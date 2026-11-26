use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use mail_parser::DateTime;
use pellet_check::{Check, CheckError, Context};
use pellet_core::{Stage, Symbol, SymbolName};

use crate::mail::Symbols;

/// How far ahead a `Date` may be before it counts as in the future, in seconds.
pub const FUTURE_SLACK: i64 = 2 * 3600;
/// How far behind a `Date` may be before it counts as in the past, in seconds.
pub const PAST_SLACK: i64 = 24 * 3600;

/// The `Date` field against the clock, at [`Stage::Data`]. A missing field is `MISSING_DATE` in
/// `HeadersCheck`.
///
/// | Symbol | When |
/// | --- | --- |
/// | `INVALID_DATE` | the field is not an RFC 5322 date |
/// | `DATE_IN_FUTURE` | more than [`FUTURE_SLACK`] ahead of now |
/// | `DATE_IN_PAST` | more than [`PAST_SLACK`] behind now |
pub struct DateCheck {
    symbols: Symbols,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl DateCheck {
    /// The check on the system clock.
    pub fn new() -> Self {
        Self::with_clock(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64)
        })
    }

    /// The check on a clock giving Unix seconds, for tests.
    pub fn with_clock(now: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        DateCheck {
            symbols: Symbols::new(&["INVALID_DATE", "DATE_IN_FUTURE", "DATE_IN_PAST"]),
            now: Arc::new(now),
        }
    }
}

impl Default for DateCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Check for DateCheck {
    fn name(&self) -> &str {
        "content.date"
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
        let Some(header) = message.header("date") else {
            return Ok(Vec::new());
        };
        let Some(date) =
            DateTime::parse_rfc822(header.value_str().trim()).filter(DateTime::is_valid)
        else {
            return Ok(vec![self.symbols.get("INVALID_DATE")]);
        };
        let offset = date.to_timestamp() - (self.now)();
        Ok(if offset > FUTURE_SLACK {
            vec![self.symbols.get("DATE_IN_FUTURE")]
        } else if offset < -PAST_SLACK {
            vec![self.symbols.get("DATE_IN_PAST")]
        } else {
            Vec::new()
        })
    }
}

#[cfg(test)]
mod tests {
    use pellet_check::testing::{Fixture, conformance};

    use super::*;

    const NOW: i64 = 1_772_445_600;

    async fn of(date: &str) -> Vec<String> {
        let fixture = Fixture::message(&format!("Date: {date}\r\n\r\nb"));
        DateCheck::with_clock(|| NOW)
            .run(&fixture.context(Stage::Data))
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.name.to_string())
            .collect()
    }

    #[tokio::test]
    async fn against_the_clock() {
        assert!(of("Mon, 2 Mar 2026 10:00:00 +0000").await.is_empty());
        assert!(
            of("Mon, 2 Mar 2026 11:30:00 +0000").await.is_empty(),
            "within the slack"
        );
        assert_eq!(
            of("Tue, 3 Mar 2026 10:00:00 +0000").await,
            ["DATE_IN_FUTURE"]
        );
        assert_eq!(
            of("Fri, 27 Feb 2026 10:00:00 +0000").await,
            ["DATE_IN_PAST"]
        );
        assert_eq!(
            of("Mon, 2 Mar 2026 12:00:00 +0200").await.len(),
            0,
            "time zones count"
        );
    }

    #[tokio::test]
    async fn invalid_dates() {
        assert_eq!(of("yesterday").await, ["INVALID_DATE"]);
        assert_eq!(of("").await, ["INVALID_DATE"]);
    }

    #[tokio::test]
    async fn passes_conformance() {
        conformance(
            &DateCheck::with_clock(|| NOW),
            &[
                Fixture::message("Date: Mon, 2 Mar 2026 10:00:00 +0000\r\n\r\n"),
                Fixture::message("Date: garbage\r\n\r\n"),
                Fixture::message(""),
            ],
        )
        .await;
    }
}
