use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use mail_parser::MessageParser;
use pellet_check::{Check, CheckError, Context, symbol_names};
use pellet_core::{Envelope, Message, Stage, Symbol, SymbolName};
use pellet_state::{Expect, Key, State, StateError};

/// How long sent messages are remembered and how much is kept of each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyConfig {
    /// How long a sent message can be answered and still be recognized.
    pub ttl: Duration,
    /// Most recipient domains kept per sent message.
    pub max_domains: usize,
    /// Most `In-Reply-To` and `References` identifiers looked up per message.
    pub max_lookups: usize,
}

impl Default for ReplyConfig {
    fn default() -> Self {
        ReplyConfig {
            ttl: Duration::from_secs(90 * 24 * 3600),
            max_domains: 32,
            max_lookups: 8,
        }
    }
}

/// Replies to mail this deployment sent, at [`Stage::Data`] after the other checks of the stage.
///
/// The host tells the check about every message it sends with [`ReplyCheck::record_sent`]. A
/// later inbound message whose `In-Reply-To` or `References` names one of them is a reply to it.
///
/// | Symbol | When |
/// | --- | --- |
/// | `TRUSTED_REPLY` | a reply from a domain the sent message went to, with `DMARC_POLICY_ALLOW` for that domain |
/// | `SPOOF_REPLYTO` | a reply that fails DMARC (`DMARC_POLICY_REJECT` or `DMARC_POLICY_QUARANTINE`), or comes from a domain the sent message did not go to without passing DMARC; mailing list traffic (`List-Id`) is left out of this second case |
///
/// Domains are compared by their registrable part. State holds only fingerprints: the key is a
/// hash of the Message-ID and the value 8-byte hashes of the recipient domains, kept for `ttl`.
/// Messages from authenticated clients are not judged. State failures leave the message
/// unjudged; they never fail the check.
pub struct ReplyCheck {
    state: Arc<dyn State>,
    config: ReplyConfig,
    declared: Vec<SymbolName>,
}

fn fingerprint(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte.to_ascii_lowercase())).wrapping_mul(0x0100_0000_01b3)
    })
}

fn sent_key(message_id: &str) -> Option<Key> {
    let id = message_id
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>');
    if id.is_empty() {
        return None;
    }
    Key::new(format!("sent/{:016x}", fingerprint(id))).ok()
}

fn domain_of(address: &str) -> Option<String> {
    let address = address.trim().trim_start_matches('<').trim_end_matches('>');
    let (_, domain) = address.rsplit_once('@')?;
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return None;
    }
    Some(psl::domain_str(&domain).unwrap_or(&domain).to_string())
}

impl ReplyCheck {
    /// Builds the check over a state store.
    pub fn new(state: Arc<dyn State>, config: ReplyConfig) -> Self {
        ReplyCheck {
            state,
            config,
            declared: symbol_names(&["TRUSTED_REPLY", "SPOOF_REPLYTO"]),
        }
    }

    /// Remembers a message this deployment sent: its Message-ID and the domains of its envelope
    /// recipients, or of its `To` and `Cc` when the envelope has none. Returns `false` when the
    /// message has no Message-ID or no recipient, so there is nothing to remember.
    pub async fn record_sent(
        &self,
        message: &Message,
        envelope: &Envelope,
    ) -> Result<bool, StateError> {
        let Some(parsed) = MessageParser::new().parse_headers(message.raw()) else {
            return Ok(false);
        };
        let Some(key) = parsed.message_id().and_then(sent_key) else {
            return Ok(false);
        };
        let mut domains: Vec<u64> = Vec::new();
        let mut add = |address: &str| {
            if let Some(domain) = domain_of(address) {
                let hash = fingerprint(&domain);
                if !domains.contains(&hash) && domains.len() < self.config.max_domains {
                    domains.push(hash);
                }
            }
        };
        if envelope.recipients.is_empty() {
            for list in [parsed.to(), parsed.cc()].into_iter().flatten() {
                for mailbox in list.mailboxes() {
                    if let Some(address) = mailbox.address() {
                        add(address);
                    }
                }
            }
        } else {
            for recipient in &envelope.recipients {
                add(recipient);
            }
        }
        if domains.is_empty() {
            return Ok(false);
        }
        let value = domains.iter().flat_map(|h| h.to_le_bytes()).collect();
        self.state
            .put(&key, value, Expect::Any, Some(self.config.ttl))
            .await?;
        Ok(true)
    }

    async fn sent_domains(&self, ids: impl Iterator<Item = &str>) -> Option<Vec<u64>> {
        for id in ids.take(self.config.max_lookups) {
            let Some(key) = sent_key(id) else { continue };
            if let Ok(Some(entry)) = self.state.get(&key).await {
                return Some(
                    entry
                        .value
                        .as_chunks::<8>()
                        .0
                        .iter()
                        .map(|c| u64::from_le_bytes(*c))
                        .collect(),
                );
            }
        }
        None
    }

    fn symbol(&self, name: &str) -> Symbol {
        Symbol::new(
            self.declared
                .iter()
                .find(|d| d.as_str() == name)
                .expect("declared symbol")
                .clone(),
        )
    }
}

#[async_trait]
impl Check for ReplyCheck {
    fn name(&self) -> &str {
        "reply"
    }

    fn stage(&self) -> Stage {
        Stage::Data
    }

    fn symbols(&self) -> &[SymbolName] {
        &self.declared
    }

    fn late(&self) -> bool {
        true
    }

    async fn run(&self, ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError> {
        let Some(message) = ctx.message else {
            return Ok(Vec::new());
        };
        if ctx.envelope.authenticated {
            return Ok(Vec::new());
        }
        let Some(parsed) = MessageParser::new().parse_headers(message.raw()) else {
            return Ok(Vec::new());
        };
        let mut ids: Vec<&str> = parsed
            .in_reply_to()
            .map(|l| l.iter().collect())
            .unwrap_or_default();
        if let Some(references) = parsed.references() {
            ids.extend(references.iter().rev());
        }
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let Some(sent) = self.sent_domains(ids.into_iter()).await else {
            return Ok(Vec::new());
        };
        let from = parsed
            .from()
            .and_then(|l| l.first())
            .and_then(|m| m.address())
            .and_then(domain_of);
        let recipient = from
            .as_ref()
            .is_some_and(|d| sent.contains(&fingerprint(d)));
        let dmarc_pass = ctx.earlier.iter().any(|s| {
            s.name.as_str() == "DMARC_POLICY_ALLOW"
                && s.options
                    .first()
                    .and_then(|d| domain_of(&format!("@{d}")))
                    .is_some_and(|d| Some(&d) == from.as_ref())
        });
        let dmarc_fail =
            ctx.earlier_has("DMARC_POLICY_REJECT") || ctx.earlier_has("DMARC_POLICY_QUARANTINE");
        let list = message.header("List-Id").is_some();
        let out = if recipient && dmarc_pass {
            Some(self.symbol("TRUSTED_REPLY"))
        } else if dmarc_fail || (!recipient && !dmarc_pass && !list) {
            Some(self.symbol("SPOOF_REPLYTO"))
        } else {
            None
        };
        Ok(out.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use pellet_check::testing::{Fixture, conformance};
    use pellet_state_memory::MemoryState;

    use super::*;

    const SENT: &str = "From: ana@example.com\r\nTo: Bo <bo@example.org>\r\nCc: cy@mail.example.net\r\nMessage-ID: <sent-1@example.com>\r\nSubject: Plan\r\n\r\nbody\r\n";

    fn check() -> ReplyCheck {
        ReplyCheck::new(Arc::new(MemoryState::new(100)), ReplyConfig::default())
    }

    fn reply(
        from: &str,
        references: &str,
        extra: &str,
        dmarc: Option<(&str, Option<&str>)>,
    ) -> Fixture {
        let mut fixture = Fixture::message(&format!(
            "From: {from}\r\nTo: ana@example.com\r\n{references}{extra}Subject: Re: Plan\r\n\r\nyes\r\n"
        ));
        fixture.envelope.recipients = vec!["ana@example.com".into()];
        if let Some((name, option)) = dmarc {
            let symbol = Symbol::new(SymbolName::new(name).unwrap());
            fixture.earlier = vec![match option {
                Some(o) => symbol.with_option(o),
                None => symbol,
            }];
        }
        fixture
    }

    async fn names(check: &ReplyCheck, fixture: &Fixture) -> Vec<String> {
        check
            .run(&fixture.context(Stage::Data))
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.name.to_string())
            .collect()
    }

    #[tokio::test]
    async fn recognizes_replies_to_sent_mail() {
        let check = check();
        let sent = Message::new(SENT.as_bytes());
        assert!(
            check
                .record_sent(&sent, &Envelope::default())
                .await
                .unwrap()
        );

        let irt = "In-Reply-To: <sent-1@example.com>\r\n";
        let trusted = reply(
            "bo@example.org",
            irt,
            "",
            Some(("DMARC_POLICY_ALLOW", Some("example.org"))),
        );
        assert_eq!(names(&check, &trusted).await, ["TRUSTED_REPLY"]);
        let subdomain = reply(
            "cy@other.example.net",
            "References: <x@example.com> <sent-1@example.com>\r\n",
            "",
            Some(("DMARC_POLICY_ALLOW", Some("other.example.net"))),
        );
        assert_eq!(
            names(&check, &subdomain).await,
            ["TRUSTED_REPLY"],
            "registrable domains match"
        );

        let forged = reply(
            "bo@example.org",
            irt,
            "",
            Some(("DMARC_POLICY_REJECT", None)),
        );
        assert_eq!(names(&check, &forged).await, ["SPOOF_REPLYTO"]);
        let stranger = reply("eve@example.com", irt, "", None);
        assert_eq!(names(&check, &stranger).await, ["SPOOF_REPLYTO"]);

        let unauthenticated = reply("bo@example.org", irt, "", None);
        assert!(
            names(&check, &unauthenticated).await.is_empty(),
            "a recipient without DMARC is neither"
        );
        let vouched = reply(
            "dee@example.com",
            irt,
            "",
            Some(("DMARC_POLICY_ALLOW", Some("example.com"))),
        );
        assert!(
            names(&check, &vouched).await.is_empty(),
            "an authenticated third party is not a spoof"
        );
        let list = reply(
            "eve@example.com",
            irt,
            "List-Id: <plans.example.com>\r\n",
            None,
        );
        assert!(
            names(&check, &list).await.is_empty(),
            "list traffic is not a spoof"
        );
        let unrelated = reply(
            "bo@example.org",
            "In-Reply-To: <other@example.com>\r\n",
            "",
            None,
        );
        assert!(names(&check, &unrelated).await.is_empty());

        let mut own = stranger.clone();
        own.envelope.authenticated = true;
        assert!(names(&check, &own).await.is_empty());
    }

    #[tokio::test]
    async fn records_envelope_recipients_as_fingerprints_only() {
        let state = Arc::new(MemoryState::new(100));
        let check = ReplyCheck::new(state.clone(), ReplyConfig::default());
        let sent = Message::new(SENT.as_bytes());
        let envelope = Envelope {
            recipients: vec!["dee@example.net".into()],
            ..Envelope::default()
        };
        assert!(check.record_sent(&sent, &envelope).await.unwrap());
        let entry = state
            .get(&sent_key("sent-1@example.com").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            entry.value,
            fingerprint("example.net").to_le_bytes(),
            "envelope wins over To and Cc"
        );

        let no_id = Message::new(&b"From: ana@example.com\r\nTo: bo@example.org\r\n\r\nb"[..]);
        assert!(
            !check
                .record_sent(&no_id, &Envelope::default())
                .await
                .unwrap()
        );
        let no_rcpt =
            Message::new(&b"From: ana@example.com\r\nMessage-ID: <x@example.com>\r\n\r\nb"[..]);
        assert!(
            !check
                .record_sent(&no_rcpt, &Envelope::default())
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn passes_conformance() {
        let check = check();
        check
            .record_sent(&Message::new(SENT.as_bytes()), &Envelope::default())
            .await
            .unwrap();
        conformance(
            &check,
            &[
                reply(
                    "eve@example.com",
                    "In-Reply-To: <sent-1@example.com>\r\n",
                    "",
                    None,
                ),
                Fixture::default(),
            ],
        )
        .await;
    }
}
