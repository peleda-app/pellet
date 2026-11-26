use async_trait::async_trait;
use pellet_check::{Check, CheckError, Context};
use pellet_core::{Stage, Symbol, SymbolName};

use crate::mail::Symbols;

const GTUBE: &[u8] = b"XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X";

/// List, priority, delivery and test-marker headers, at [`Stage::Data`].
///
/// | Symbol | When |
/// | --- | --- |
/// | `HAS_LIST_UNSUB` | `List-Unsubscribe` is present |
/// | `MAILLIST` | `List-Id` or `Mailing-List` is present, or `Precedence` is `list` |
/// | `PRECEDENCE_BULK` | `Precedence` is `bulk`, `list` or `junk` |
/// | `HAS_X_PRIO_ZERO` … `HAS_X_PRIO_FIVE` | `X-Priority` starts with 0, 1, 2, 3 or 5 |
/// | `MV_CASE` | `MIME-Version` spelled with other capitals |
/// | `CTE_CASE` | the top-level `Content-Transfer-Encoding` value is not lowercase |
/// | `PREVIOUSLY_DELIVERED` | a `Delivered-To` field names an envelope recipient |
/// | `GTUBE_TEST` | the body carries the GTUBE test string |
/// | `COMPLETELY_EMPTY` | no body text and no subject |
/// | `HEADER_EMPTY_DELIMITER` | a field with no space between its colon and its value |
pub struct HeaderFlagsCheck {
    symbols: Symbols,
}

impl HeaderFlagsCheck {
    /// The check.
    pub fn new() -> Self {
        HeaderFlagsCheck {
            symbols: Symbols::new(&[
                "HAS_LIST_UNSUB",
                "MAILLIST",
                "PRECEDENCE_BULK",
                "HAS_X_PRIO_ZERO",
                "HAS_X_PRIO_ONE",
                "HAS_X_PRIO_TWO",
                "HAS_X_PRIO_THREE",
                "HAS_X_PRIO_FIVE",
                "MV_CASE",
                "CTE_CASE",
                "PREVIOUSLY_DELIVERED",
                "GTUBE_TEST",
                "COMPLETELY_EMPTY",
                "HEADER_EMPTY_DELIMITER",
            ]),
        }
    }
}

impl Default for HeaderFlagsCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Check for HeaderFlagsCheck {
    fn name(&self) -> &str {
        "content.flags"
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
        let value = |name: &str| {
            message
                .header(name)
                .map(|h| h.value_str().trim().to_ascii_lowercase())
        };
        let mut out = Vec::new();
        let mut emit = |name: &str| out.push(self.symbols.get(name));

        if message.header("list-unsubscribe").is_some() {
            emit("HAS_LIST_UNSUB");
        }
        let precedence = value("precedence").unwrap_or_default();
        if message.header("list-id").is_some()
            || message.header("mailing-list").is_some()
            || precedence == "list"
        {
            emit("MAILLIST");
        }
        if matches!(precedence.as_str(), "bulk" | "list" | "junk") {
            emit("PRECEDENCE_BULK");
        }
        match value("x-priority").and_then(|p| p.chars().next()) {
            Some('0') => emit("HAS_X_PRIO_ZERO"),
            Some('1') => emit("HAS_X_PRIO_ONE"),
            Some('2') => emit("HAS_X_PRIO_TWO"),
            Some('3') => emit("HAS_X_PRIO_THREE"),
            Some('5') => emit("HAS_X_PRIO_FIVE"),
            _ => {}
        }
        if message
            .headers_named("mime-version")
            .any(|h| h.name() != "MIME-Version")
        {
            emit("MV_CASE");
        }
        if let Some(cte) = message.header("content-transfer-encoding") {
            let cte = cte.value_str();
            if cte.trim() != cte.trim().to_ascii_lowercase() {
                emit("CTE_CASE");
            }
        }
        let recipients: Vec<String> = ctx
            .envelope
            .recipients
            .iter()
            .map(|r| r.to_ascii_lowercase())
            .collect();
        if message.headers_named("delivered-to").any(|h| {
            recipients.contains(
                &h.value_str()
                    .trim()
                    .trim_matches(['<', '>'])
                    .to_ascii_lowercase(),
            )
        }) {
            emit("PREVIOUSLY_DELIVERED");
        }
        if memchr::memmem::find(message.body(), GTUBE).is_some() {
            emit("GTUBE_TEST");
        }
        let no_subject = message
            .header("subject")
            .is_none_or(|s| s.value().iter().all(u8::is_ascii_whitespace));
        if no_subject && message.body().iter().all(u8::is_ascii_whitespace) {
            emit("COMPLETELY_EMPTY");
        }
        if tight_colon(message.raw()) {
            emit("HEADER_EMPTY_DELIMITER");
        }
        Ok(out)
    }
}

/// Whether a header line has a value glued to its colon, as in `Subject:hello`.
fn tight_colon(raw: &[u8]) -> bool {
    for line in raw.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            return false;
        }
        if matches!(line[0], b' ' | b'\t') {
            continue;
        }
        if let Some(colon) = line.iter().position(|&b| b == b':')
            && line[..colon].iter().all(|&b| (33..=126).contains(&b))
            && line
                .get(colon + 1)
                .is_some_and(|&b| b != b' ' && b != b'\t')
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use pellet_check::testing::{Fixture, conformance};

    use super::*;

    async fn names(fixture: &Fixture) -> Vec<String> {
        let mut names: Vec<String> = HeaderFlagsCheck::new()
            .run(&fixture.context(Stage::Data))
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.name.to_string())
            .collect();
        names.sort();
        names
    }

    async fn of(raw: &str) -> Vec<String> {
        names(&Fixture::message(raw)).await
    }

    #[tokio::test]
    async fn list_and_bulk_headers() {
        assert_eq!(
            of("List-Id: <news.example.com>\r\nList-Unsubscribe: <mailto:u@example.com>\r\nPrecedence: Bulk\r\nSubject: x\r\n\r\nbody").await,
            ["HAS_LIST_UNSUB", "MAILLIST", "PRECEDENCE_BULK"]
        );
        assert_eq!(
            of("Precedence: list\r\nSubject: x\r\n\r\nb").await,
            ["MAILLIST", "PRECEDENCE_BULK"]
        );
    }

    #[tokio::test]
    async fn priorities() {
        for (value, symbol) in [
            ("1 (Highest)", "HAS_X_PRIO_ONE"),
            ("3", "HAS_X_PRIO_THREE"),
            ("5", "HAS_X_PRIO_FIVE"),
            ("0", "HAS_X_PRIO_ZERO"),
        ] {
            assert_eq!(
                of(&format!("X-Priority: {value}\r\nSubject: x\r\n\r\nb")).await,
                [symbol]
            );
        }
        assert!(of("X-Priority: 4\r\nSubject: x\r\n\r\nb").await.is_empty());
    }

    #[tokio::test]
    async fn spelling_of_mime_headers() {
        assert_eq!(
            of("Mime-Version: 1.0\r\nSubject: x\r\n\r\nb").await,
            ["MV_CASE"]
        );
        assert!(
            of("MIME-Version: 1.0\r\nSubject: x\r\n\r\nb")
                .await
                .is_empty()
        );
        assert_eq!(
            of("Content-Transfer-Encoding: 7BIT\r\nSubject: x\r\n\r\nb").await,
            ["CTE_CASE"]
        );
        assert!(
            of("Content-Transfer-Encoding: 7bit\r\nSubject: x\r\n\r\nb")
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn delivered_to_an_envelope_recipient() {
        let mut fixture = Fixture::message("Delivered-To: Bo@example.org\r\nSubject: x\r\n\r\nb");
        fixture.envelope.recipients = vec!["bo@example.org".into()];
        assert_eq!(names(&fixture).await, ["PREVIOUSLY_DELIVERED"]);
        fixture.envelope.recipients = vec!["ana@example.org".into()];
        assert!(names(&fixture).await.is_empty());
    }

    #[tokio::test]
    async fn gtube_and_empty() {
        let gtube = format!(
            "Subject: test\r\n\r\n{}\r\n",
            String::from_utf8_lossy(GTUBE)
        );
        assert_eq!(of(&gtube).await, ["GTUBE_TEST"]);
        assert_eq!(
            of("From: a@example.com\r\n\r\n  \r\n").await,
            ["COMPLETELY_EMPTY"]
        );
        assert!(
            of("Subject: hi\r\n\r\n").await.is_empty(),
            "a subject is content"
        );
    }

    #[tokio::test]
    async fn glued_colons() {
        assert_eq!(
            of("Subject:hello\r\n\r\nb").await,
            ["HEADER_EMPTY_DELIMITER"]
        );
        assert!(of("Subject: hello\r\nX-Empty:\r\n\r\nb:c").await.is_empty());
        assert!(!tight_colon(b"A: b\r\n continued:x\r\n\r\nBody:text"));
    }

    #[tokio::test]
    async fn passes_conformance() {
        conformance(
            &HeaderFlagsCheck::new(),
            &[
                Fixture::message("List-Id: x\r\nX-Priority: 1\r\nMime-Version: 1.0\r\n\r\n"),
                Fixture::message("Subject: x\r\n\r\nbody"),
                Fixture::message(""),
            ],
        )
        .await;
    }
}
