use std::net::IpAddr;

use async_trait::async_trait;
use pellet_check::{Check, CheckError, Context};
use pellet_core::{Stage, Symbol, SymbolName};

use crate::mail::{Mail, Symbols, registrable};

/// The shape of `Message-ID`, at [`Stage::Data`]. A missing field is `MISSING_MID` in
/// `HeadersCheck`.
///
/// | Symbol | When |
/// | --- | --- |
/// | `MID_MISSING_BRACKETS` | an `id@domain` without `<` `>` |
/// | `INVALID_MSGID` | not `<left@right>` with both sides non-empty and no spaces |
/// | `MID_RHS_IP_LITERAL` | the right side is `[address]` |
/// | `MID_BARE_IP` | the right side is a bare address |
/// | `MID_RHS_NOT_FQDN` | the right side has no dot |
/// | `MID_RHS_WWW` | the right side starts with `www.` |
/// | `MID_RHS_MATCH_FROM` | the right side is the From domain |
/// | `MID_RHS_MATCH_FROMTLD` | another host under the From domain's registrable domain |
/// | `MID_RHS_MATCH_TO` | the right side is a To domain other than the From domain |
/// | `MID_CONTAINS_FROM`, `MID_CONTAINS_TO` | the id contains the From address, or a To address |
pub struct MessageIdCheck {
    symbols: Symbols,
}

impl MessageIdCheck {
    /// The check.
    pub fn new() -> Self {
        MessageIdCheck {
            symbols: Symbols::new(&[
                "MID_MISSING_BRACKETS",
                "INVALID_MSGID",
                "MID_RHS_IP_LITERAL",
                "MID_BARE_IP",
                "MID_RHS_NOT_FQDN",
                "MID_RHS_WWW",
                "MID_RHS_MATCH_FROM",
                "MID_RHS_MATCH_FROMTLD",
                "MID_RHS_MATCH_TO",
                "MID_CONTAINS_FROM",
                "MID_CONTAINS_TO",
            ]),
        }
    }
}

impl Default for MessageIdCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Check for MessageIdCheck {
    fn name(&self) -> &str {
        "content.message_id"
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
        let Some(header) = message.header("message-id") else {
            return Ok(Vec::new());
        };
        let raw = header.value_str().trim().to_string();
        let mut out = Vec::new();
        let mut emit = |name: &str| out.push(self.symbols.get(name));

        let bracketed = raw.starts_with('<') && raw.ends_with('>') && raw.len() >= 2;
        let id = if bracketed {
            &raw[1..raw.len() - 1]
        } else {
            raw.as_str()
        };
        if !bracketed && id.contains('@') {
            emit("MID_MISSING_BRACKETS");
        }
        let Some((left, right)) = id.rsplit_once('@') else {
            emit("INVALID_MSGID");
            return Ok(out);
        };
        if left.is_empty() || right.is_empty() || id.contains(char::is_whitespace) {
            emit("INVALID_MSGID");
            return Ok(out);
        }
        let right = right.to_ascii_lowercase();
        if right.starts_with('[') && right.ends_with(']') {
            emit("MID_RHS_IP_LITERAL");
        } else if right.parse::<IpAddr>().is_ok() {
            emit("MID_BARE_IP");
        } else if !right.contains('.') {
            emit("MID_RHS_NOT_FQDN");
        }
        if right.starts_with("www.") {
            emit("MID_RHS_WWW");
        }

        let mail = Mail::parse(message);
        let id_lower = id.to_lowercase();
        let from = mail.from.first().filter(|m| m.valid());
        if let Some(from) = from {
            if right == from.domain {
                emit("MID_RHS_MATCH_FROM");
            } else if registrable(&right) == registrable(&from.domain) {
                emit("MID_RHS_MATCH_FROMTLD");
            }
            if id_lower.contains(&from.email) {
                emit("MID_CONTAINS_FROM");
            }
        }
        let from_domain = from.map(|f| f.domain.as_str());
        if mail
            .to
            .iter()
            .any(|t| t.domain == right && Some(t.domain.as_str()) != from_domain)
        {
            emit("MID_RHS_MATCH_TO");
        }
        if mail
            .to
            .iter()
            .any(|t| t.valid() && id_lower.contains(&t.email))
        {
            emit("MID_CONTAINS_TO");
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use pellet_check::testing::{Fixture, conformance};

    use super::*;

    async fn of(mid: &str) -> Vec<String> {
        let fixture = Fixture::message(&format!(
            "From: ana@mail.example.com\r\nTo: bo@example.org\r\nMessage-ID: {mid}\r\n\r\nb"
        ));
        let mut names: Vec<String> = MessageIdCheck::new()
            .run(&fixture.context(Stage::Data))
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.name.to_string())
            .collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn shapes() {
        assert_eq!(of("<1.2@mail.example.com>").await, ["MID_RHS_MATCH_FROM"]);
        assert_eq!(
            of("<1.2@lists.example.com>").await,
            ["MID_RHS_MATCH_FROMTLD"]
        );
        assert!(of("<1.2@other.example.net>").await.is_empty());
        assert_eq!(of("1.2@other.example.net").await, ["MID_MISSING_BRACKETS"]);
        assert_eq!(of("<no-at-sign>").await, ["INVALID_MSGID"]);
        assert_eq!(of("<has space@example.net>").await, ["INVALID_MSGID"]);
        assert_eq!(of("<x@[192.0.2.1]>").await, ["MID_RHS_IP_LITERAL"]);
        assert_eq!(of("<x@192.0.2.1>").await, ["MID_BARE_IP"]);
        assert_eq!(of("<x@localhost>").await, ["MID_RHS_NOT_FQDN"]);
        assert_eq!(of("<x@www.example.net>").await, ["MID_RHS_WWW"]);
        assert_eq!(of("<x@example.org>").await, ["MID_RHS_MATCH_TO"]);
        assert_eq!(
            of("<bo@example.org.1@example.net>").await,
            ["MID_CONTAINS_TO"]
        );
        assert_eq!(
            of("<ana@mail.example.com-7@mail.example.com>").await,
            ["MID_CONTAINS_FROM", "MID_RHS_MATCH_FROM"]
        );
    }

    #[tokio::test]
    async fn missing_field_is_left_to_headers_check() {
        let fixture = Fixture::message("From: a@example.com\r\n\r\nb");
        assert!(
            MessageIdCheck::new()
                .run(&fixture.context(Stage::Data))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn passes_conformance() {
        conformance(
            &MessageIdCheck::new(),
            &[
                Fixture::message("From: a@example.com\r\nMessage-ID: <x@example.com>\r\n\r\n"),
                Fixture::message("Message-ID: broken\r\n\r\n"),
                Fixture::message(""),
            ],
        )
        .await;
    }
}
