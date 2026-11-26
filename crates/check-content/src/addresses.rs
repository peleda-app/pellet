use async_trait::async_trait;
use pellet_check::{Check, CheckError, Context};
use pellet_core::{Message, Stage, Symbol, SymbolName};

use crate::mail::{Mail, Mbox, Symbols, registrable};

const SYMBOLS: [&str; 46] = [
    "FROM_HAS_DN",
    "FROM_NO_DN",
    "FROM_DN_EQ_ADDR",
    "FROM_NEQ_DISPLAY_NAME",
    "FROM_INVALID",
    "NO_SPACE_IN_FROM",
    "FROM_EQ_ENV_FROM",
    "FROM_NEQ_ENV_FROM",
    "ENV_FROM_INVALID",
    "FROM_BOUNCE",
    "HAS_REPLYTO",
    "REPLYTO_UNPARSABLE",
    "REPLYTO_EQ_FROM",
    "REPLYTO_ADDR_EQ_FROM",
    "REPLYTO_DOM_EQ_FROM_DOM",
    "REPLYTO_DOM_NEQ_FROM_DOM",
    "REPLYTO_DN_EQ_FROM_DN",
    "REPLYTO_EQ_TO_ADDR",
    "TO_DN_ALL",
    "TO_DN_SOME",
    "TO_DN_NONE",
    "TO_DN_EQ_ADDR_ALL",
    "TO_DN_EQ_ADDR_SOME",
    "TO_EQ_FROM",
    "TO_DOM_EQ_FROM_DOM",
    "TO_MATCH_ENVRCPT_ALL",
    "TO_MATCH_ENVRCPT_SOME",
    "TO_WRAPPED_IN_SPACES",
    "RCPT_COUNT_ZERO",
    "RCPT_COUNT_ONE",
    "RCPT_COUNT_TWO",
    "RCPT_COUNT_THREE",
    "RCPT_COUNT_FIVE",
    "RCPT_COUNT_SEVEN",
    "RCPT_COUNT_TWELVE",
    "RCPT_COUNT_GT_50",
    "SORTED_RECIPS",
    "RCPT_IN_SUBJECT",
    "RCPT_DOMAIN_IN_SUBJECT",
    "RCPT_LOCAL_IN_SUBJECT",
    "RCPT_BOUNCEMOREONE",
    "FORGED_SENDER",
    "FORGED_RECIPIENTS",
    "SPOOF_DISPLAY_NAME",
    "HEADER_FORGED_MDN",
    "HEADER_RCONFIRM_MISMATCH",
];

/// How From, Reply-To, To and Cc relate to each other and to the envelope, at [`Stage::Data`].
///
/// | Symbols | When |
/// | --- | --- |
/// | `FROM_HAS_DN`, `FROM_NO_DN` | the first From mailbox has a display name, or not |
/// | `FROM_DN_EQ_ADDR` | the display name is the address itself |
/// | `FROM_NEQ_DISPLAY_NAME` | the display name carries a different address in the same registrable domain |
/// | `FROM_INVALID` | From is present but holds no usable address |
/// | `NO_SPACE_IN_FROM` | the display name runs straight into `<` |
/// | `FROM_EQ_ENV_FROM`, `FROM_NEQ_ENV_FROM` | From against a non-null `MAIL FROM` |
/// | `ENV_FROM_INVALID` | `MAIL FROM` is not an address with a domain |
/// | `FROM_BOUNCE` | From is `mailer-daemon` or `postmaster` |
/// | `HAS_REPLYTO`, `REPLYTO_UNPARSABLE` | Reply-To is present; it holds no usable address |
/// | `REPLYTO_EQ_FROM` | same address and name as From |
/// | `REPLYTO_ADDR_EQ_FROM` | same address as From, another name |
/// | `REPLYTO_DOM_EQ_FROM_DOM`, `REPLYTO_DOM_NEQ_FROM_DOM` | another address in the same, or another, domain |
/// | `REPLYTO_DN_EQ_FROM_DN` | another address under the same display name |
/// | `REPLYTO_EQ_TO_ADDR` | Reply-To is one of the To addresses, outside mailing lists (`List-Id`, `List-Post`, `Mailing-List` or `Precedence: list`), whose replies go to the list |
/// | `TO_DN_ALL`, `TO_DN_SOME`, `TO_DN_NONE` | how many To mailboxes have display names |
/// | `TO_DN_EQ_ADDR_ALL`, `TO_DN_EQ_ADDR_SOME` | display names that are the address itself |
/// | `TO_EQ_FROM` | the From address is among the To addresses |
/// | `TO_DOM_EQ_FROM_DOM` | every To address is another address in the From domain |
/// | `TO_MATCH_ENVRCPT_ALL`, `TO_MATCH_ENVRCPT_SOME` | envelope recipients found in To and Cc |
/// | `TO_WRAPPED_IN_SPACES` | `< address >` in To |
/// | `RCPT_COUNT_ZERO` … `RCPT_COUNT_GT_50` | distinct To, Cc and Bcc addresses: 0, 1, 2, 3–4, 5–6, 7–11, 12–50, more |
/// | `SORTED_RECIPS` | seven or more To and Cc addresses in alphabetical order |
/// | `RCPT_IN_SUBJECT`, `RCPT_DOMAIN_IN_SUBJECT`, `RCPT_LOCAL_IN_SUBJECT` | the subject names an envelope recipient's address, domain, or local part of four or more characters |
/// | `RCPT_BOUNCEMOREONE` | a null-sender message to more than one envelope recipient |
/// | `FORGED_SENDER` | `MAIL FROM` and From are in different registrable domains |
/// | `FORGED_RECIPIENTS` | To and Cc name none of the envelope recipients (not for mailing lists, authenticated clients, or mail to an alias at a forwarding service from [`AddressCheck::alias_domains`]) |
/// | `SPOOF_DISPLAY_NAME` | the display name carries an address in another registrable domain than From |
/// | `HEADER_FORGED_MDN`, `HEADER_RCONFIRM_MISMATCH` | read receipts (`Disposition-Notification-To`, `X-Confirm-Reading-To`) go to an address other than the sender's |
pub struct AddressCheck {
    symbols: Symbols,
    alias_domains: Vec<String>,
}

impl AddressCheck {
    /// The check, with no forwarding services known.
    pub fn new() -> Self {
        AddressCheck {
            symbols: Symbols::new(&SYMBOLS),
            alias_domains: Vec::new(),
        }
    }

    /// Domains of forwarding services that hand out aliases and deliver to another address
    /// (the bundled `alias-relays` list). A To or Cc address at one of them, or at a subdomain,
    /// is expected to differ from the envelope recipient, so it never makes `FORGED_RECIPIENTS`.
    pub fn alias_domains<S: AsRef<str>>(mut self, domains: impl IntoIterator<Item = S>) -> Self {
        self.alias_domains = domains
            .into_iter()
            .map(|d| d.as_ref().trim().trim_matches('.').to_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        self
    }

    fn is_alias(&self, address: &str) -> bool {
        address.rsplit_once('@').is_some_and(|(_, domain)| {
            self.alias_domains.iter().any(|alias| {
                domain == alias
                    || domain
                        .strip_suffix(alias.as_str())
                        .is_some_and(|rest| rest.ends_with('.'))
            })
        })
    }
}

impl Default for AddressCheck {
    fn default() -> Self {
        Self::new()
    }
}

fn address_in(text: &str) -> Option<String> {
    text.split(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '(' | ')' | '"' | '\'' | ','))
        .find(|w| {
            w.split_once('@')
                .is_some_and(|(l, d)| !l.is_empty() && d.contains('.'))
        })
        .map(|w| w.to_lowercase())
}

fn count_bucket(n: usize) -> &'static str {
    match n {
        0 => "RCPT_COUNT_ZERO",
        1 => "RCPT_COUNT_ONE",
        2 => "RCPT_COUNT_TWO",
        3..=4 => "RCPT_COUNT_THREE",
        5..=6 => "RCPT_COUNT_FIVE",
        7..=11 => "RCPT_COUNT_SEVEN",
        12..=50 => "RCPT_COUNT_TWELVE",
        _ => "RCPT_COUNT_GT_50",
    }
}

#[async_trait]
impl Check for AddressCheck {
    fn name(&self) -> &str {
        "content.addresses"
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
        let mail = Mail::parse(message);
        let envelope = ctx.envelope;
        let mut out = Vec::new();
        let mut emit = |name: &str| out.push(self.symbols.get(name));

        let env_from = envelope
            .mail_from
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| Mbox::new(None, s));
        if env_from.as_ref().is_some_and(|m| !m.valid()) {
            emit("ENV_FROM_INVALID");
        }

        let from = mail.from.first().filter(|m| m.valid());
        if let Some(raw) = message.header("from") {
            let raw = raw.value_str();
            if let Some(at) = raw.find('<')
                && at > 0
                && !raw[..at].ends_with(char::is_whitespace)
                && !raw[..at].trim().is_empty()
            {
                emit("NO_SPACE_IN_FROM");
            }
            if from.is_none() {
                emit("FROM_INVALID");
            }
        }
        if let Some(from) = from {
            if from.name.is_empty() {
                emit("FROM_NO_DN");
            } else {
                emit("FROM_HAS_DN");
                if from.name_is_address() {
                    emit("FROM_DN_EQ_ADDR");
                } else if let Some(shown) = address_in(&from.name).filter(|a| *a != from.email) {
                    let shown_domain = shown.rsplit_once('@').map_or("", |(_, d)| d);
                    emit(if registrable(shown_domain) != registrable(&from.domain) {
                        "SPOOF_DISPLAY_NAME"
                    } else {
                        "FROM_NEQ_DISPLAY_NAME"
                    });
                }
            }
            if let Some(env_from) = &env_from {
                emit(if env_from.email == from.email {
                    "FROM_EQ_ENV_FROM"
                } else {
                    "FROM_NEQ_ENV_FROM"
                });
                if env_from.valid() && registrable(&env_from.domain) != registrable(&from.domain) {
                    emit("FORGED_SENDER");
                }
            }
            let differs = |field: &str| {
                message
                    .header(field)
                    .and_then(|h| address_in(&h.value_str()))
                    .is_some_and(|a| {
                        a != from.email && env_from.as_ref().is_none_or(|e| e.email != a)
                    })
            };
            if differs("disposition-notification-to") {
                emit("HEADER_FORGED_MDN");
            }
            if differs("x-confirm-reading-to") {
                emit("HEADER_RCONFIRM_MISMATCH");
            }
            if matches!(from.local.as_str(), "mailer-daemon" | "postmaster") {
                emit("FROM_BOUNCE");
            }
        }

        if message.header("reply-to").is_some() {
            emit("HAS_REPLYTO");
            match mail.reply_to.first().filter(|m| m.valid()) {
                None => emit("REPLYTO_UNPARSABLE"),
                Some(reply) => {
                    if let Some(from) = from {
                        if reply.email == from.email {
                            emit(if reply.name == from.name {
                                "REPLYTO_EQ_FROM"
                            } else {
                                "REPLYTO_ADDR_EQ_FROM"
                            });
                        } else {
                            emit(if reply.domain == from.domain {
                                "REPLYTO_DOM_EQ_FROM_DOM"
                            } else {
                                "REPLYTO_DOM_NEQ_FROM_DOM"
                            });
                            if !reply.name.is_empty() && reply.name.eq_ignore_ascii_case(&from.name)
                            {
                                emit("REPLYTO_DN_EQ_FROM_DN");
                            }
                        }
                    }
                    if !is_list(message) && mail.to.iter().any(|t| t.email == reply.email) {
                        emit("REPLYTO_EQ_TO_ADDR");
                    }
                }
            }
        }

        if !mail.to.is_empty() {
            let named = mail.to.iter().filter(|t| !t.name.is_empty()).count();
            emit(match named {
                0 => "TO_DN_NONE",
                n if n == mail.to.len() => "TO_DN_ALL",
                _ => "TO_DN_SOME",
            });
            let self_named = mail.to.iter().filter(|t| t.name_is_address()).count();
            if self_named == mail.to.len() {
                emit("TO_DN_EQ_ADDR_ALL");
            } else if self_named > 0 {
                emit("TO_DN_EQ_ADDR_SOME");
            }
            if let Some(from) = from {
                if mail.to.iter().any(|t| t.email == from.email) {
                    emit("TO_EQ_FROM");
                } else if mail.to.iter().all(|t| t.domain == from.domain) {
                    emit("TO_DOM_EQ_FROM_DOM");
                }
            }
        }
        if message
            .header("to")
            .is_some_and(|h| h.value_str().contains("< ") || h.value_str().contains(" >"))
        {
            emit("TO_WRAPPED_IN_SPACES");
        }

        let header_rcpts: Vec<&str> = mail
            .to
            .iter()
            .chain(&mail.cc)
            .map(|m| m.email.as_str())
            .collect();
        let envelope_rcpts: Vec<String> = envelope
            .recipients
            .iter()
            .map(|r| r.trim().to_lowercase())
            .collect();
        if !envelope_rcpts.is_empty() {
            let matched = envelope_rcpts
                .iter()
                .filter(|r| header_rcpts.contains(&r.as_str()))
                .count();
            if matched == envelope_rcpts.len() {
                emit("TO_MATCH_ENVRCPT_ALL");
            } else if matched > 0 {
                emit("TO_MATCH_ENVRCPT_SOME");
            } else if !header_rcpts.is_empty()
                && !envelope.authenticated
                && !is_list(message)
                && !header_rcpts.iter().any(|r| self.is_alias(r))
            {
                emit("FORGED_RECIPIENTS");
            }
        }

        let mut distinct: Vec<&str> = mail.recipients().map(|m| m.email.as_str()).collect();
        distinct.sort();
        distinct.dedup();
        if message.header("to").is_some() || message.header("cc").is_some() || !distinct.is_empty()
        {
            emit(count_bucket(distinct.len()));
        }
        if header_rcpts.len() >= 7 && header_rcpts.windows(2).all(|w| w[0] <= w[1]) {
            emit("SORTED_RECIPS");
        }

        if let Some(subject) = mail.subject.as_deref().map(str::to_lowercase) {
            let in_subject = |pick: &dyn Fn(&Mbox) -> &str, min: usize| {
                envelope_rcpts.iter().any(|r| {
                    let m = Mbox::new(None, r);
                    let part = pick(&m);
                    part.len() >= min && subject.contains(part)
                })
            };
            if in_subject(&|m| m.email.as_str(), 3) {
                emit("RCPT_IN_SUBJECT");
            } else if in_subject(&|m| m.domain.as_str(), 4) {
                emit("RCPT_DOMAIN_IN_SUBJECT");
            } else if in_subject(&|m| m.local.as_str(), 4) {
                emit("RCPT_LOCAL_IN_SUBJECT");
            }
        }

        if envelope.mail_from.as_deref() == Some("") && envelope.recipients.len() > 1 {
            emit("RCPT_BOUNCEMOREONE");
        }
        Ok(out)
    }
}

/// Mailing list traffic: `List-Id`, `List-Post`, `Mailing-List` or `Precedence: list`.
fn is_list(message: &Message) -> bool {
    ["list-id", "list-post", "mailing-list"]
        .iter()
        .any(|name| message.header(name).is_some())
        || message
            .header("precedence")
            .is_some_and(|h| h.value_str().trim().eq_ignore_ascii_case("list"))
}

#[cfg(test)]
mod tests;
