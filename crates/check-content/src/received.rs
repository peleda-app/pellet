use async_trait::async_trait;
use pellet_check::{Check, CheckError, Context};
use pellet_core::{Header, Stage, Symbol, SymbolName};

use crate::mail::Symbols;

/// The `Received` trail, at [`Stage::Data`]. The topmost field is the last hop.
///
/// | Symbol | When |
/// | --- | --- |
/// | `RCVD_COUNT_ZERO` … `RCVD_COUNT_TWELVE` | 0, 1, 2, 3–4, 5–6, 7–11 or 12 and more fields |
/// | `RCVD_TLS_ALL` | every hop says it used TLS |
/// | `RCVD_TLS_LAST`, `RCVD_NO_TLS_LAST` | the last hop did, or did not |
/// | `RCVD_VIA_SMTP_AUTH` | a hop accepted the message from an authenticated client |
/// | `RCVD_HELO_USER` | a hop names its client `user` |
/// | `RCVD_ILLEGAL_CHARS` | a field has 8-bit or control characters |
/// | `RCVD_DOUBLE_IP_SPAM` | two or more hops name their client by a bare address |
///
/// TLS shows as `ESMTPS`, `ESMTPSA`, `SMTPS`, `using TLS` or a TLS version; authentication as
/// `ESMTPA`, `ESMTPSA` or `authenticated`.
pub struct ReceivedCheck {
    symbols: Symbols,
}

impl ReceivedCheck {
    /// The check.
    pub fn new() -> Self {
        ReceivedCheck {
            symbols: Symbols::new(&[
                "RCVD_COUNT_ZERO",
                "RCVD_COUNT_ONE",
                "RCVD_COUNT_TWO",
                "RCVD_COUNT_THREE",
                "RCVD_COUNT_FIVE",
                "RCVD_COUNT_SEVEN",
                "RCVD_COUNT_TWELVE",
                "RCVD_TLS_ALL",
                "RCVD_TLS_LAST",
                "RCVD_NO_TLS_LAST",
                "RCVD_VIA_SMTP_AUTH",
                "RCVD_HELO_USER",
                "RCVD_ILLEGAL_CHARS",
                "RCVD_DOUBLE_IP_SPAM",
            ]),
        }
    }
}

impl Default for ReceivedCheck {
    fn default() -> Self {
        Self::new()
    }
}

fn words(header: &Header) -> String {
    header.value_str().to_ascii_lowercase()
}

fn tls(text: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric() && c != '.')
        .any(|w| {
            matches!(
                w,
                "esmtps"
                    | "esmtpsa"
                    | "smtps"
                    | "lmtps"
                    | "tls"
                    | "tlsv1.2"
                    | "tlsv1.3"
                    | "tls1.2"
                    | "tls1.3"
            )
        })
}

fn authenticated(text: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|w| matches!(w, "esmtpa" | "esmtpsa" | "authenticated"))
}

fn helo_user(text: &str) -> bool {
    text.starts_with("from user ") || text.contains("helo=user)") || text.contains("helo user)")
}

fn bare_ip_client(text: &str) -> bool {
    text.strip_prefix("from ")
        .and_then(|rest| rest.split_whitespace().next())
        .map(|client| client.trim_matches(['[', ']']))
        .is_some_and(|client| client.parse::<std::net::IpAddr>().is_ok())
}

fn bucket(n: usize) -> &'static str {
    match n {
        0 => "RCVD_COUNT_ZERO",
        1 => "RCVD_COUNT_ONE",
        2 => "RCVD_COUNT_TWO",
        3..=4 => "RCVD_COUNT_THREE",
        5..=6 => "RCVD_COUNT_FIVE",
        7..=11 => "RCVD_COUNT_SEVEN",
        _ => "RCVD_COUNT_TWELVE",
    }
}

#[async_trait]
impl Check for ReceivedCheck {
    fn name(&self) -> &str {
        "content.received"
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
        let fields: Vec<&Header> = message.headers_named("received").collect();
        let texts: Vec<String> = fields.iter().map(|h| words(h)).collect();
        let mut out = vec![self.symbols.get(bucket(fields.len()))];
        if let Some(last) = texts.first() {
            if texts.iter().all(|t| tls(t)) {
                out.push(self.symbols.get("RCVD_TLS_ALL"));
            }
            out.push(self.symbols.get(if tls(last) {
                "RCVD_TLS_LAST"
            } else {
                "RCVD_NO_TLS_LAST"
            }));
        }
        if texts.iter().any(|t| authenticated(t)) {
            out.push(self.symbols.get("RCVD_VIA_SMTP_AUTH"));
        }
        if texts.iter().any(|t| helo_user(t)) {
            out.push(self.symbols.get("RCVD_HELO_USER"));
        }
        if texts.iter().filter(|t| bare_ip_client(t)).count() >= 2 {
            out.push(self.symbols.get("RCVD_DOUBLE_IP_SPAM"));
        }
        if fields.iter().any(|h| {
            h.value()
                .iter()
                .any(|&b| b >= 0x80 || (b < 0x20 && b != b'\t'))
        }) {
            out.push(self.symbols.get("RCVD_ILLEGAL_CHARS"));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use pellet_check::testing::{Fixture, conformance};
    use pellet_core::Message;

    use super::*;

    async fn names(raw: &[u8]) -> Vec<String> {
        let fixture = Fixture {
            message: Some(Message::new(raw)),
            ..Fixture::default()
        };
        let mut names: Vec<String> = ReceivedCheck::new()
            .run(&fixture.context(Stage::Data))
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.name.to_string())
            .collect();
        names.sort();
        names
    }

    const TLS_HOP: &str = "Received: from mail.example.com (mail.example.com [192.0.2.25]) by mx.example.org with ESMTPS id 1; Tue, 3 Mar 2026 09:15:01 +0100\r\n";
    const PLAIN_HOP: &str = "Received: from client (unknown [198.51.100.7]) by mail.example.com with SMTP id 2; Tue, 3 Mar 2026 09:15:00 +0100\r\n";

    #[tokio::test]
    async fn counts_and_tls() {
        assert_eq!(names(b"Subject: x\r\n\r\n").await, ["RCVD_COUNT_ZERO"]);
        let one = format!("{TLS_HOP}\r\n");
        assert_eq!(
            names(one.as_bytes()).await,
            ["RCVD_COUNT_ONE", "RCVD_TLS_ALL", "RCVD_TLS_LAST"]
        );
        let two = format!("{TLS_HOP}{PLAIN_HOP}\r\n");
        assert_eq!(
            names(two.as_bytes()).await,
            ["RCVD_COUNT_TWO", "RCVD_TLS_LAST"]
        );
        let reversed = format!("{PLAIN_HOP}{TLS_HOP}\r\n");
        assert_eq!(
            names(reversed.as_bytes()).await,
            ["RCVD_COUNT_TWO", "RCVD_NO_TLS_LAST"]
        );
        assert_eq!(bucket(4), "RCVD_COUNT_THREE");
        assert_eq!(bucket(6), "RCVD_COUNT_FIVE");
        assert_eq!(bucket(9), "RCVD_COUNT_SEVEN");
        assert_eq!(bucket(30), "RCVD_COUNT_TWELVE");
    }

    #[tokio::test]
    async fn authentication_helo_and_bad_bytes() {
        let auth = b"Received: from [192.0.2.40] by mail.example.org with ESMTPSA id 3\r\n\r\n";
        assert!(
            names(auth)
                .await
                .contains(&"RCVD_VIA_SMTP_AUTH".to_string())
        );
        let user =
            b"Received: from user (unknown [198.51.100.9]) by mx.example.org with SMTP\r\n\r\n";
        assert!(names(user).await.contains(&"RCVD_HELO_USER".to_string()));
        let bad = b"Received: from h\xc3\xa9 by mx.example.org with SMTP\r\n\r\n";
        assert!(names(bad).await.contains(&"RCVD_ILLEGAL_CHARS".to_string()));
    }

    #[tokio::test]
    async fn bare_address_clients() {
        let raw = b"Received: from [198.51.100.7] by a.example.net with SMTP\r\nReceived: from 203.0.113.9 by b.example.net with SMTP\r\n\r\n";
        assert!(
            names(raw)
                .await
                .contains(&"RCVD_DOUBLE_IP_SPAM".to_string())
        );
        let ordinary = format!("{TLS_HOP}{PLAIN_HOP}\r\n");
        assert!(
            !names(ordinary.as_bytes())
                .await
                .contains(&"RCVD_DOUBLE_IP_SPAM".to_string())
        );
    }

    #[tokio::test]
    async fn passes_conformance() {
        conformance(
            &ReceivedCheck::new(),
            &[
                Fixture::message(&format!("{TLS_HOP}{PLAIN_HOP}\r\n")),
                Fixture::message(""),
            ],
        )
        .await;
    }
}
