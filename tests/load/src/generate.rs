//! Invented messages of known shapes, the same on every run.

use std::fmt::Write;

/// A shape of message the load runs feed through Pellet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A short personal text message.
    Plain,
    /// An HTML newsletter with a plain alternative and this many links.
    Newsletter(usize),
    /// A short message with a base64 attachment of this many bytes.
    Attachment(usize),
    /// A plain body of this many bytes of ordinary words.
    LongText(usize),
    /// A body of this many bytes without a single space.
    NoSpaces(usize),
    /// This many header fields.
    ManyHeaders(usize),
    /// Multipart containers nested this deep.
    DeepMime(usize),
    /// Text of this many bytes made of characters that grow when lowercased.
    GrowingUnicode(usize),
}

impl Kind {
    /// A short stable name for reports.
    pub fn label(self) -> String {
        match self {
            Kind::Plain => "plain".into(),
            Kind::Newsletter(n) => format!("newsletter-{n}-links"),
            Kind::Attachment(n) => format!("attachment-{}", size(n)),
            Kind::LongText(n) => format!("text-{}", size(n)),
            Kind::NoSpaces(n) => format!("no-spaces-{}", size(n)),
            Kind::ManyHeaders(n) => format!("headers-{n}"),
            Kind::DeepMime(n) => format!("mime-depth-{n}"),
            Kind::GrowingUnicode(n) => format!("unicode-{}", size(n)),
        }
    }
}

fn size(bytes: usize) -> String {
    if bytes >= 1 << 20 {
        format!("{}mb", bytes >> 20)
    } else {
        format!("{}kb", bytes >> 10)
    }
}

const WORDS: [&str; 24] = [
    "the",
    "quarterly",
    "report",
    "meeting",
    "please",
    "review",
    "draft",
    "budget",
    "team",
    "schedule",
    "notes",
    "project",
    "update",
    "today",
    "about",
    "results",
    "offer",
    "free",
    "account",
    "service",
    "change",
    "details",
    "attached",
    "thanks",
];

/// A tiny deterministic generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn word(&mut self) -> &'static str {
        WORDS[(self.next() % WORDS.len() as u64) as usize]
    }
}

fn headers(n: usize, subject: &str) -> String {
    format!(
        "From: Sender {n} <sender{n}@example.com>\r\nTo: Reader <reader@example.org>\r\nSubject: {subject}\r\nDate: Thu, 12 Mar 2026 09:00:00 +0000\r\nMessage-ID: <load-{n}@example.com>\r\nMIME-Version: 1.0\r\n"
    )
}

fn words(rng: &mut Rng, bytes: usize) -> String {
    let mut out = String::with_capacity(bytes + 16);
    let mut line = 0;
    while out.len() < bytes {
        let word = rng.word();
        out.push_str(word);
        line += word.len() + 1;
        if line > 72 {
            out.push_str("\r\n");
            line = 0;
        } else {
            out.push(' ');
        }
    }
    out
}

fn base64_lines(rng: &mut Rng, bytes: usize) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let chars = bytes.div_ceil(3) * 4;
    let mut out = String::with_capacity(chars + chars / 76 * 2);
    for i in 0..chars {
        out.push(ALPHABET[(rng.next() % 64) as usize] as char);
        if i % 76 == 75 {
            out.push_str("\r\n");
        }
    }
    out
}

/// Room for the whole message up front: growing a large string reallocates, and on some systems
/// the freed blocks stay counted as resident, which would blur the memory a load run reports.
fn capacity(kind: Kind) -> usize {
    let content = match kind {
        Kind::Plain | Kind::ManyHeaders(_) | Kind::DeepMime(_) => 0,
        Kind::Newsletter(links) => links * 200,
        Kind::Attachment(bytes) => bytes.div_ceil(3) * 4 * 78 / 76,
        Kind::LongText(bytes) | Kind::NoSpaces(bytes) | Kind::GrowingUnicode(bytes) => bytes,
    };
    let headers = match kind {
        Kind::ManyHeaders(count) => count * 40,
        Kind::DeepMime(depth) => depth * 80,
        _ => 0,
    };
    content + headers + 4096
}

/// Message number `n` of a kind, as raw bytes.
pub fn message(kind: Kind, n: usize) -> Vec<u8> {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ (n as u64 + 1));
    let mut out = String::with_capacity(capacity(kind));
    match kind {
        Kind::Plain => {
            out += &headers(n, "Notes from the meeting");
            out += "Content-Type: text/plain; charset=utf-8\r\n\r\n";
            out += &words(&mut rng, 600);
        }
        Kind::Newsletter(links) => {
            out += &headers(n, "This month's product news");
            out += "Content-Type: multipart/alternative; boundary=\"alt\"\r\n\r\n--alt\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n";
            for i in 0..links {
                let _ = write!(
                    out,
                    "{} https://news{}.example.com/a/{i}\r\n",
                    rng.word(),
                    i % 50
                );
            }
            out += "--alt\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body>";
            for i in 0..links {
                let _ = write!(
                    out,
                    "<p>{} {} <a href=\"https://news{}.example.com/a/{i}\">{}</a></p>",
                    rng.word(),
                    rng.word(),
                    i % 50,
                    rng.word()
                );
            }
            out += "</body></html>\r\n--alt--\r\n";
        }
        Kind::Attachment(bytes) => {
            out += &headers(n, "The report you asked for");
            out += "Content-Type: multipart/mixed; boundary=\"mix\"\r\n\r\n--mix\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n";
            out += &words(&mut rng, 300);
            out += "\r\n--mix\r\nContent-Type: application/pdf; name=\"report.pdf\"\r\nContent-Disposition: attachment; filename=\"report.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0x";
            out += &base64_lines(&mut rng, bytes);
            out += "\r\n--mix--\r\n";
        }
        Kind::LongText(bytes) => {
            out += &headers(n, "A long letter");
            out += "Content-Type: text/plain; charset=utf-8\r\n\r\n";
            out += &words(&mut rng, bytes);
        }
        Kind::NoSpaces(bytes) => {
            out += &headers(n, "No spaces");
            out += "Content-Type: text/plain; charset=utf-8\r\n\r\n";
            out.extend(std::iter::repeat_n('x', bytes));
        }
        Kind::ManyHeaders(count) => {
            out += &headers(n, "Many headers");
            for i in 0..count {
                let _ = writeln!(out, "X-Load-{i}: {}\r", rng.word());
            }
            out += "Content-Type: text/plain; charset=utf-8\r\n\r\nbody\r\n";
        }
        Kind::DeepMime(depth) => {
            out += &headers(n, "Nested parts");
            for level in 0..depth {
                let _ = write!(
                    out,
                    "Content-Type: multipart/mixed; boundary=\"b{level}\"\r\n\r\n--b{level}\r\n"
                );
            }
            out += "Content-Type: text/plain; charset=utf-8\r\n\r\ninnermost\r\n";
            for level in (0..depth).rev() {
                let _ = write!(out, "--b{level}--\r\n");
            }
        }
        Kind::GrowingUnicode(bytes) => {
            out += &headers(n, "Unicode");
            out += "Content-Type: text/plain; charset=utf-8\r\n\r\n";
            while out.len() < bytes {
                out += "\u{130}\u{130} https://example.com/x \u{130} www.example.org ";
            }
        }
    }
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_sized() {
        assert_eq!(
            message(Kind::Newsletter(10), 3),
            message(Kind::Newsletter(10), 3)
        );
        assert_ne!(message(Kind::Plain, 1), message(Kind::Plain, 2));
        let attachment = message(Kind::Attachment(1 << 20), 0);
        assert!(attachment.len() > 1 << 20);
        assert!(message(Kind::LongText(100_000), 0).len() >= 100_000);
        assert_eq!(Kind::Attachment(8 << 20).label(), "attachment-8mb");
        for kind in [
            Kind::Attachment(1 << 20),
            Kind::Newsletter(400),
            Kind::ManyHeaders(2000),
            Kind::DeepMime(60),
        ] {
            let raw = message(kind, 0);
            assert!(
                raw.capacity() >= raw.len() && raw.capacity() < raw.len() * 2 + 8192,
                "{kind:?}"
            );
        }
    }
}
