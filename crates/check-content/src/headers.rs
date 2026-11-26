use async_trait::async_trait;
use pellet_check::{Check, CheckError, Context, symbol_names};
use pellet_core::{Stage, Symbol, SymbolName};

use crate::address::count_mailboxes;

const SYMBOLS: [&str; 10] = [
    "MISSING_FROM",
    "MULTIPLE_FROM",
    "MISSING_TO",
    "MISSING_SUBJECT",
    "EMPTY_SUBJECT",
    "MISSING_DATE",
    "MISSING_MID",
    "MISSING_MIME_VERSION",
    "MULTIPLE_UNIQUE_HEADERS",
    "MISSING_ESSENTIAL_HEADERS",
];

/// Fields RFC 5322 allows at most once.
const UNIQUE: [&str; 11] = [
    "date",
    "from",
    "sender",
    "reply-to",
    "to",
    "cc",
    "bcc",
    "message-id",
    "in-reply-to",
    "references",
    "subject",
];

const ESSENTIAL: [&str; 5] = ["from", "to", "subject", "date", "message-id"];

/// Presence and count of essential header fields, at [`Stage::Data`].
///
/// | Symbol | When |
/// | --- | --- |
/// | `MISSING_FROM` | no `From` |
/// | `MULTIPLE_FROM` | more than one `From` field, or more than one mailbox in it |
/// | `MISSING_TO` | no `To` |
/// | `MISSING_SUBJECT` | no `Subject` |
/// | `EMPTY_SUBJECT` | `Subject` with only whitespace |
/// | `MISSING_DATE` | no `Date`, unless the client authenticated |
/// | `MISSING_MID` | no `Message-ID`, unless the client authenticated |
/// | `MISSING_MIME_VERSION` | `Content-Type` without `MIME-Version` |
/// | `MULTIPLE_UNIQUE_HEADERS` | a field RFC 5322 allows once appears more often; options name the fields |
/// | `MISSING_ESSENTIAL_HEADERS` | none of `From`, `To`, `Subject`, `Date`, `Message-ID` |
///
/// Authenticated clients are exempt from `MISSING_DATE` and `MISSING_MID` because submission
/// servers add those fields.
pub struct HeadersCheck {
    declared: Vec<SymbolName>,
}

impl HeadersCheck {
    /// The check.
    pub fn new() -> Self {
        HeadersCheck {
            declared: symbol_names(&SYMBOLS),
        }
    }

    fn symbol(&self, name: &str) -> Symbol {
        let declared = self
            .declared
            .iter()
            .find(|d| d.as_str() == name)
            .expect("declared symbol");
        Symbol::new(declared.clone())
    }
}

impl Default for HeadersCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Check for HeadersCheck {
    fn name(&self) -> &str {
        "content.headers"
    }

    fn stage(&self) -> Stage {
        Stage::Data
    }

    fn symbols(&self) -> &[SymbolName] {
        &self.declared
    }

    async fn run(&self, ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError> {
        let message = ctx
            .message
            .ok_or_else(|| CheckError::Failed("no message at the data stage".into()))?;
        let has = |name: &str| message.header(name).is_some();
        let mut out = Vec::new();

        let from_fields = message.header_count("from");
        if from_fields == 0 {
            out.push(self.symbol("MISSING_FROM"));
        } else if from_fields > 1
            || message
                .header("from")
                .is_some_and(|h| count_mailboxes(h.value()) > 1)
        {
            out.push(self.symbol("MULTIPLE_FROM"));
        }

        if !has("to") {
            out.push(self.symbol("MISSING_TO"));
        }

        match message.header("subject") {
            None => out.push(self.symbol("MISSING_SUBJECT")),
            Some(subject) if subject.value().iter().all(u8::is_ascii_whitespace) => {
                out.push(self.symbol("EMPTY_SUBJECT"))
            }
            Some(_) => {}
        }

        if !ctx.envelope.authenticated {
            if !has("date") {
                out.push(self.symbol("MISSING_DATE"));
            }
            if !has("message-id") {
                out.push(self.symbol("MISSING_MID"));
            }
        }

        if has("content-type") && !has("mime-version") {
            out.push(self.symbol("MISSING_MIME_VERSION"));
        }

        let repeated: Vec<&str> = UNIQUE
            .iter()
            .copied()
            .filter(|name| message.header_count(name) > 1)
            .collect();
        if !repeated.is_empty() {
            let mut symbol = self.symbol("MULTIPLE_UNIQUE_HEADERS");
            for name in repeated {
                symbol.push_option(name);
            }
            out.push(symbol);
        }

        if ESSENTIAL.iter().all(|name| !has(name)) {
            out.push(self.symbol("MISSING_ESSENTIAL_HEADERS"));
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use pellet_check::testing::{Fixture, conformance};

    use super::*;

    const COMPLETE: &str = "From: Ana <ana@example.com>\r\n\
        To: bo@example.org\r\n\
        Subject: Lunch\r\n\
        Date: Mon, 2 Mar 2026 10:00:00 +0000\r\n\
        Message-ID: <1@example.com>\r\n\
        MIME-Version: 1.0\r\n\
        Content-Type: text/plain\r\n\
        \r\n\
        See you at noon.\r\n";

    async fn symbols(fixture: &Fixture) -> Vec<String> {
        let check = HeadersCheck::new();
        let mut names: Vec<String> = check
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
        symbols(&Fixture::message(raw)).await
    }

    #[tokio::test]
    async fn complete_message_is_clean() {
        assert!(of(COMPLETE).await.is_empty());
    }

    #[tokio::test]
    async fn reports_each_missing_field() {
        for (field, symbol) in [
            ("From", "MISSING_FROM"),
            ("To", "MISSING_TO"),
            ("Subject", "MISSING_SUBJECT"),
            ("Date", "MISSING_DATE"),
            ("Message-ID", "MISSING_MID"),
            ("MIME-Version", "MISSING_MIME_VERSION"),
        ] {
            let raw: String = COMPLETE
                .split_inclusive("\r\n")
                .filter(|line| !line.starts_with(&format!("{field}:")))
                .collect();
            assert_eq!(of(&raw).await, [symbol], "without {field}");
        }
    }

    #[tokio::test]
    async fn empty_subject() {
        let raw = COMPLETE.replace("Subject: Lunch", "Subject:   ");
        assert_eq!(of(&raw).await, ["EMPTY_SUBJECT"]);
    }

    #[tokio::test]
    async fn multiple_from_fields_or_mailboxes() {
        let two_fields = COMPLETE.replace("To:", "From: eve@example.net\r\nTo:");
        assert_eq!(
            of(&two_fields).await,
            ["MULTIPLE_FROM", "MULTIPLE_UNIQUE_HEADERS"]
        );

        let two_mailboxes = COMPLETE.replace(
            "From: Ana <ana@example.com>",
            "From: ana@example.com, eve@example.net",
        );
        assert_eq!(of(&two_mailboxes).await, ["MULTIPLE_FROM"]);

        let quoted_comma = COMPLETE.replace("From: Ana", "From: \"Doe, Ana\"");
        assert!(of(&quoted_comma).await.is_empty());
    }

    #[tokio::test]
    async fn repeated_unique_fields_are_named() {
        let raw = COMPLETE.replace(
            "MIME-Version",
            "Subject: Again\r\nDate: Tue, 3 Mar 2026 10:00:00 +0000\r\nMIME-Version",
        );
        let check = HeadersCheck::new();
        let fixture = Fixture::message(&raw);
        let out = check.run(&fixture.context(Stage::Data)).await.unwrap();
        let symbol = out
            .iter()
            .find(|s| s.name.as_str() == "MULTIPLE_UNIQUE_HEADERS")
            .unwrap();
        assert_eq!(symbol.options, ["date", "subject"]);
    }

    #[tokio::test]
    async fn bare_message_misses_everything() {
        assert_eq!(
            of("X-Mailer: test\r\n\r\nbody").await,
            [
                "MISSING_DATE",
                "MISSING_ESSENTIAL_HEADERS",
                "MISSING_FROM",
                "MISSING_MID",
                "MISSING_SUBJECT",
                "MISSING_TO"
            ]
        );
    }

    #[tokio::test]
    async fn authenticated_clients_may_omit_date_and_message_id() {
        let raw: String = COMPLETE
            .split_inclusive("\r\n")
            .filter(|l| !l.starts_with("Date:") && !l.starts_with("Message-ID:"))
            .collect();
        let mut fixture = Fixture::message(&raw);
        fixture.envelope.authenticated = true;
        assert!(symbols(&fixture).await.is_empty());
    }

    #[tokio::test]
    async fn header_names_are_case_insensitive() {
        let raw = COMPLETE
            .replace("From:", "FROM:")
            .replace("Message-ID:", "message-id:");
        assert!(of(&raw).await.is_empty());
    }

    #[tokio::test]
    async fn passes_conformance() {
        let fixtures = [
            Fixture::message(COMPLETE),
            Fixture::message("X-Mailer: test\r\n\r\n"),
            Fixture::message(""),
            Fixture::message(&COMPLETE.replace("To:", "From: eve@example.net\r\nTo:")),
        ];
        conformance(&HeadersCheck::new(), &fixtures).await;
    }
}
