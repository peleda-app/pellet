use mail_parser::{AddressList, MessageParser};
use pellet_check::symbol_names;
use pellet_core::{Message, Symbol, SymbolName};

/// The symbols a check declares, and a way to emit one by name.
pub(crate) struct Symbols(Vec<SymbolName>);

impl Symbols {
    pub(crate) fn new(names: &[&str]) -> Self {
        Symbols(symbol_names(names))
    }

    pub(crate) fn get(&self, name: &str) -> Symbol {
        Symbol::new(
            self.0
                .iter()
                .find(|d| d.as_str() == name)
                .unwrap_or_else(|| panic!("{name} is not declared"))
                .clone(),
        )
    }

    pub(crate) fn all(&self) -> &[SymbolName] {
        &self.0
    }
}

/// One mailbox from an address header, lowercased address split into parts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Mbox {
    pub(crate) name: String,
    pub(crate) email: String,
    pub(crate) local: String,
    pub(crate) domain: String,
}

impl Mbox {
    pub(crate) fn new(name: Option<&str>, email: &str) -> Self {
        let email = email.trim().to_lowercase();
        let (local, domain) = email.rsplit_once('@').unwrap_or((email.as_str(), ""));
        Mbox {
            name: name
                .unwrap_or_default()
                .trim()
                .trim_matches('"')
                .trim()
                .to_string(),
            local: local.to_string(),
            domain: domain.to_string(),
            email,
        }
    }

    pub(crate) fn valid(&self) -> bool {
        !self.local.is_empty() && self.domain.contains('.') && !self.domain.starts_with('.')
    }

    pub(crate) fn name_is_address(&self) -> bool {
        !self.name.is_empty()
            && self.name.to_lowercase().trim_matches(['<', '>', '\'']) == self.email
    }
}

/// The address headers and subject of a message, decoded by `mail-parser`.
#[derive(Debug, Default)]
pub(crate) struct Mail {
    pub(crate) from: Vec<Mbox>,
    pub(crate) reply_to: Vec<Mbox>,
    pub(crate) to: Vec<Mbox>,
    pub(crate) cc: Vec<Mbox>,
    pub(crate) bcc: Vec<Mbox>,
    pub(crate) subject: Option<String>,
}

fn mailboxes(list: Option<AddressList<'_>>) -> Vec<Mbox> {
    list.map(|l| {
        l.mailboxes()
            .filter_map(|m| Some(Mbox::new(m.name(), m.address()?)))
            .collect()
    })
    .unwrap_or_default()
}

impl Mail {
    pub(crate) fn parse(message: &Message) -> Mail {
        let Some(parsed) = MessageParser::new().parse(message.raw()) else {
            return Mail::default();
        };
        Mail {
            from: mailboxes(parsed.from()),
            reply_to: mailboxes(parsed.reply_to()),
            to: mailboxes(parsed.to()),
            cc: mailboxes(parsed.cc()),
            bcc: mailboxes(parsed.bcc()),
            subject: parsed.subject().map(str::to_string),
        }
    }

    pub(crate) fn recipients(&self) -> impl Iterator<Item = &Mbox> {
        self.to.iter().chain(&self.cc).chain(&self.bcc)
    }
}

/// Decodes base64 until `max` bytes are out, skipping anything that is not a base64 digit, so
/// the start of a large attachment can be read without decoding the rest.
pub(crate) fn base64_prefix(text: &[u8], max: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for &c in text {
        if out.len() >= max {
            break;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => continue,
        };
        buffer = (buffer << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out
}

/// The domain under its public suffix: `mail.example.co.uk` gives `example.co.uk`.
pub(crate) fn registrable(domain: &str) -> &str {
    psl::domain_str(domain).unwrap_or(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mailboxes_and_subject() {
        let message = Message::new(
            &b"From: \"Ana L\" <Ana@Example.COM>\r\nTo: a@example.org, B <b@example.org>\r\nSubject: =?utf-8?q?Caf=C3=A9?=\r\n\r\n"[..],
        );
        let mail = Mail::parse(&message);
        assert_eq!(mail.from[0].email, "ana@example.com");
        assert_eq!(mail.from[0].name, "Ana L");
        assert_eq!(mail.from[0].domain, "example.com");
        assert_eq!(mail.to.len(), 2);
        assert_eq!(mail.subject.as_deref(), Some("Café"));
        assert_eq!(mail.recipients().count(), 2);
    }

    #[test]
    fn base64_prefixes() {
        assert_eq!(base64_prefix(b"SGVs\r\nbG8=", usize::MAX), b"Hello");
        assert_eq!(base64_prefix(b"SGVsbG8gd29ybGQ=", 4), b"Hell");
        assert_eq!(base64_prefix(b"", 4), b"");
    }

    #[test]
    fn mailbox_helpers() {
        assert!(Mbox::new(None, "a@example.com").valid());
        assert!(!Mbox::new(None, "nobody").valid());
        assert!(!Mbox::new(None, "a@localhost").valid());
        assert!(Mbox::new(Some("a@example.com"), "A@example.com").name_is_address());
        assert!(!Mbox::new(Some("Ana"), "a@example.com").name_is_address());
        assert_eq!(registrable("mail.example.co.uk"), "example.co.uk");
    }
}
