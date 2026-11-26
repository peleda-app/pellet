use async_trait::async_trait;
use pellet_check::{Check, CheckError, Context};
use pellet_core::{Stage, Symbol, SymbolName};

use crate::mail::Symbols;

/// Header fields checked, with the symbols for needless base64, needless quoted-printable and
/// raw 8-bit text.
const FIELDS: [(&str, &str, &str, Option<&str>); 4] = [
    (
        "from",
        "FROM_EXCESS_BASE64",
        "FROM_EXCESS_QP",
        Some("FROM_NEEDS_ENCODING"),
    ),
    (
        "to",
        "TO_EXCESS_BASE64",
        "TO_EXCESS_QP",
        Some("TO_NEEDS_ENCODING"),
    ),
    (
        "reply-to",
        "REPLYTO_EXCESS_BASE64",
        "REPLYTO_EXCESS_QP",
        None,
    ),
    (
        "subject",
        "SUBJ_EXCESS_BASE64",
        "SUBJ_EXCESS_QP",
        Some("SUBJECT_NEEDS_ENCODING"),
    ),
];

/// Encoded words in From, To, Reply-To and Subject, at [`Stage::Data`].
///
/// `*_EXCESS_BASE64` and `*_EXCESS_QP`: the field has an RFC 2047 encoded word in that encoding
/// whose decoded text is plain ASCII, so the encoding hides nothing but the text from filters.
/// `*_NEEDS_ENCODING`: the field carries raw 8-bit bytes instead of encoded words.
/// `INVALID_FROM_8BIT`: those bytes in From are not even valid UTF-8.
pub struct EncodingCheck {
    symbols: Symbols,
}

impl EncodingCheck {
    /// The check.
    pub fn new() -> Self {
        let names: Vec<&str> = FIELDS
            .iter()
            .flat_map(|(_, b, q, n)| [Some(*b), Some(*q), *n])
            .flatten()
            .collect();
        let names: Vec<&str> = names.into_iter().chain(["INVALID_FROM_8BIT"]).collect();
        EncodingCheck {
            symbols: Symbols::new(&names),
        }
    }
}

impl Default for EncodingCheck {
    fn default() -> Self {
        Self::new()
    }
}

/// Each encoded word as its encoding (`b` or `q`) and decoded bytes.
fn encoded_words(value: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let text = String::from_utf8_lossy(value);
    let mut out = Vec::new();
    let mut rest = text.as_ref();
    while let Some(start) = rest.find("=?") {
        let after = &rest[start + 2..];
        let mut parts = after.splitn(3, '?');
        let (Some(_charset), Some(encoding), Some(tail)) =
            (parts.next(), parts.next(), parts.next())
        else {
            break;
        };
        let Some(end) = tail.find("?=") else { break };
        let payload = &tail[..end];
        match encoding.to_ascii_lowercase().as_str() {
            "b" => out.push((b'b', base64(payload))),
            "q" => out.push((b'q', quoted(payload))),
            _ => {}
        }
        rest = &tail[end + 2..];
    }
    out
}

fn base64(text: &str) -> Vec<u8> {
    crate::mail::base64_prefix(text.as_bytes(), usize::MAX)
}

fn quoted(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'_' => out.push(b' '),
            b'=' if i + 2 < bytes.len() => {
                let hex = |b: u8| (b as char).to_digit(16);
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(high), Some(low)) => {
                        out.push((high * 16 + low) as u8);
                        i += 2;
                    }
                    _ => out.push(b'='),
                }
            }
            other => out.push(other),
        }
        i += 1;
    }
    out
}

#[async_trait]
impl Check for EncodingCheck {
    fn name(&self) -> &str {
        "content.encoding"
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
        let mut out = Vec::new();
        for (field, base64_symbol, qp_symbol, raw_symbol) in FIELDS {
            let Some(header) = message.header(field) else {
                continue;
            };
            let words = encoded_words(header.value());
            let needless = |kind: u8| {
                words
                    .iter()
                    .any(|(k, decoded)| *k == kind && !decoded.is_empty() && decoded.is_ascii())
            };
            if needless(b'b') {
                out.push(self.symbols.get(base64_symbol));
            }
            if needless(b'q') {
                out.push(self.symbols.get(qp_symbol));
            }
            if let Some(raw_symbol) = raw_symbol
                && !header.value().is_ascii()
            {
                out.push(self.symbols.get(raw_symbol));
                if field == "from" && std::str::from_utf8(header.value()).is_err() {
                    out.push(self.symbols.get("INVALID_FROM_8BIT"));
                }
            }
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
        let mut names: Vec<String> = EncodingCheck::new()
            .run(&fixture.context(Stage::Data))
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.name.to_string())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn decoders() {
        assert_eq!(base64("SGVsbG8="), b"Hello");
        assert_eq!(quoted("Caf=C3=A9_now"), "Café now".as_bytes());
        assert_eq!(quoted("50=25"), b"50%");
        assert_eq!(quoted("odd=Z"), b"odd=Z");
        assert_eq!(quoted("end="), b"end=");
        let words = encoded_words(b"=?utf-8?B?SGk=?= and =?iso-8859-1?q?caf=E9?=");
        assert_eq!(
            words,
            [(b'b', b"Hi".to_vec()), (b'q', vec![b'c', b'a', b'f', 0xe9])]
        );
    }

    #[tokio::test]
    async fn needless_encodings() {
        assert_eq!(
            names(b"Subject: =?utf-8?B?QnV5IG5vdw==?=\r\n\r\n").await,
            ["SUBJ_EXCESS_BASE64"]
        );
        assert_eq!(
            names(b"From: =?utf-8?Q?Support?= <a@example.com>\r\n\r\n").await,
            ["FROM_EXCESS_QP"]
        );
        assert_eq!(
            names(b"Reply-To: =?utf-8?B?U2FsZXM=?= <s@example.com>\r\n\r\n").await,
            ["REPLYTO_EXCESS_BASE64"]
        );
        assert!(
            names(b"Subject: =?utf-8?B?Q2Fmw6k=?=\r\n\r\n")
                .await
                .is_empty(),
            "real non-ASCII text"
        );
        assert!(names(b"Subject: plain\r\n\r\n").await.is_empty());
    }

    #[tokio::test]
    async fn raw_eight_bit() {
        assert_eq!(
            names(b"Subject: caf\xc3\xa9\r\n\r\n").await,
            ["SUBJECT_NEEDS_ENCODING"]
        );
        assert_eq!(
            names(b"To: Bj\xc3\xb6rn <b@example.org>\r\n\r\n").await,
            ["TO_NEEDS_ENCODING"]
        );
        assert_eq!(
            names(b"From: Bj\xf6rn <b@example.org>\r\n\r\n").await,
            ["FROM_NEEDS_ENCODING", "INVALID_FROM_8BIT"]
        );
    }

    #[tokio::test]
    async fn passes_conformance() {
        conformance(
            &EncodingCheck::new(),
            &[
                Fixture::message(
                    "Subject: =?utf-8?B?QnV5?=\r\nFrom: =?utf-8?Q?A?= <a@example.com>\r\n\r\n",
                ),
                Fixture::message(""),
            ],
        )
        .await;
    }
}
