use mail_parser::{MessageParser, PartKind, html_to_text};
use pellet_core::Message;
use sha1::{Digest, Sha1};

const ATOMIC_LINES: usize = 4;
const MIN_LINE: usize = 8;
const PIECES: [(usize, usize); 2] = [(20, 3), (60, 3)];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Drops what changes between copies of the same bulk message: tokens of ten or more
/// characters, addresses, URLs and all whitespace.
pub(crate) fn normalize(line: &str) -> String {
    let mut kept = String::with_capacity(line.len());
    let mut token = String::new();
    let flush = |token: &mut String, kept: &mut String| {
        if !token.is_empty() {
            kept.push_str(strip_token(token));
            token.clear();
        }
    };
    for c in line.chars() {
        if c.is_whitespace() {
            flush(&mut token, &mut kept);
            kept.push(c);
        } else {
            token.push(c);
        }
    }
    flush(&mut token, &mut kept);
    kept.retain(|c| !c.is_whitespace());
    kept
}

fn starts_with_ignore_case(text: &str, prefix: &str) -> bool {
    text.len() >= prefix.len()
        && text.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

/// Entity names HTML accepts without the closing semicolon.
const LEGACY: [&str; 106] = [
    "AElig", "AMP", "Aacute", "Acirc", "Agrave", "Aring", "Atilde", "Auml", "COPY", "Ccedil",
    "ETH", "Eacute", "Ecirc", "Egrave", "Euml", "GT", "Iacute", "Icirc", "Igrave", "Iuml", "LT",
    "Ntilde", "Oacute", "Ocirc", "Ograve", "Oslash", "Otilde", "Ouml", "QUOT", "REG", "THORN",
    "Uacute", "Ucirc", "Ugrave", "Uuml", "Yacute", "aacute", "acirc", "acute", "aelig", "agrave",
    "amp", "aring", "atilde", "auml", "brvbar", "ccedil", "cedil", "cent", "copy", "curren", "deg",
    "divide", "eacute", "ecirc", "egrave", "eth", "euml", "frac12", "frac14", "frac34", "gt",
    "iacute", "icirc", "iexcl", "igrave", "iquest", "iuml", "laquo", "lt", "macr", "micro",
    "middot", "nbsp", "not", "ntilde", "oacute", "ocirc", "ograve", "ordf", "ordm", "oslash",
    "otilde", "ouml", "para", "plusmn", "pound", "quot", "raquo", "reg", "sect", "shy", "sup1",
    "sup2", "sup3", "szlig", "thorn", "times", "uacute", "ucirc", "ugrave", "uml", "uuml",
    "yacute", "yen", "yuml",
];

fn named(name: &str) -> Option<String> {
    let entity = format!("&{name};");
    let decoded = html_to_text(&entity);
    (decoded != entity && !decoded.is_empty()).then_some(decoded)
}

/// One entity at the start of `text` (just after `&`): what it decodes to and how many bytes it
/// takes. Numeric references and names with a semicolon decode in full; without one, the longest
/// legacy name that starts the run decodes and the rest stays text.
fn entity(text: &str) -> Option<(String, usize)> {
    if let Some(number) = text.strip_prefix('#') {
        let (digits, radix, skip) = match number.strip_prefix(['x', 'X']) {
            Some(hex) => (hex, 16, 2),
            None => (number, 10, 1),
        };
        let len = digits
            .bytes()
            .take_while(|b| (*b as char).is_digit(radix))
            .count();
        if len == 0 {
            return None;
        }
        let value = u32::from_str_radix(&digits[..len], radix).unwrap_or(u32::MAX);
        let c = char::from_u32(value)
            .filter(|&c| c != '\0')
            .unwrap_or('\u{fffd}');
        let semicolon = usize::from(digits[len..].starts_with(';'));
        return Some((c.to_string(), skip + len + semicolon));
    }
    let run = text.bytes().take_while(u8::is_ascii_alphanumeric).count();
    if run == 0 {
        return None;
    }
    if text[run..].starts_with(';')
        && let Some(decoded) = named(&text[..run])
    {
        return Some((decoded, run + 1));
    }
    let name = LEGACY
        .iter()
        .filter(|n| text[..run].starts_with(**n))
        .max_by_key(|n| n.len())?;
    Some((named(name)?, name.len()))
}

fn decode_entities(piece: &str) -> String {
    let mut out = String::with_capacity(piece.len());
    let mut rest = piece;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at + 1..];
        match entity(rest) {
            Some((decoded, len)) => {
                out.push_str(&decoded);
                rest = &rest[len..];
            }
            None => out.push('&'),
        }
    }
    out.push_str(rest);
    out
}

fn tag_end(tag: &str) -> usize {
    let mut quote = None;
    for (i, c) in tag.char_indices() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '>') => return i + 1,
            _ => {}
        }
    }
    tag.len()
}

/// The text nodes of an HTML document, entities decoded, each trimmed and joined by a space;
/// `script` and `style` contents and comments are left out. A text node that spans lines keeps
/// its line breaks.
pub(crate) fn html_text(html: &str) -> String {
    let mut pieces = Vec::new();
    let mut rest = html;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix("<!--") {
            rest = after.find("-->").map_or("", |end| &after[end + 3..]);
            continue;
        }
        let is_tag = rest.starts_with('<')
            && rest[1..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || matches!(c, '/' | '!' | '?'));
        if is_tag {
            let end = tag_end(rest);
            let name: String = rest[1..end]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect::<String>()
                .to_ascii_lowercase();
            rest = &rest[end..];
            if name == "script" || name == "style" {
                let close = format!("</{name}");
                let mut skipped = rest;
                loop {
                    match skipped.find('<') {
                        Some(at) if starts_with_ignore_case(&skipped[at..], &close) => {
                            skipped = &skipped[at..];
                            break;
                        }
                        Some(at) => skipped = &skipped[at + 1..],
                        None => {
                            skipped = "";
                            break;
                        }
                    }
                }
                rest = skipped;
            }
            continue;
        }
        let first = rest.chars().next().map_or(1, char::len_utf8);
        let end = rest[first..].find('<').map_or(rest.len(), |e| e + first);
        let piece = decode_entities(&rest[..end]);
        let piece = piece.trim();
        if !piece.is_empty() {
            pieces.push(piece.to_string());
        }
        rest = &rest[end..];
    }
    pieces.join(" ")
}

fn strip_token(token: &str) -> &str {
    let chars: Vec<char> = token.chars().collect();
    if chars.len() >= 10 {
        return "";
    }
    if chars
        .iter()
        .enumerate()
        .any(|(i, &c)| c == '@' && i > 0 && i + 1 < chars.len())
    {
        return "";
    }
    for (colon, _) in token.match_indices(':') {
        let letters = token[..colon]
            .chars()
            .rev()
            .take_while(char::is_ascii_lowercase)
            .count();
        if letters > 0 && colon + 1 < token.len() {
            return &token[..colon - letters];
        }
    }
    token
}

fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.split([
        '\n', '\r', '\u{0b}', '\u{0c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}',
        '\u{2029}',
    ])
}

/// The Pyzor digest of a message's text: hex SHA-1 over its normalized lines of eight or more
/// characters, all of them when there are at most four, else three from 20% and three from 60%
/// of the way through. Text parts without a declared charset keep only their ASCII; undecodable
/// bytes are dropped; HTML parts are reduced to their text nodes. `None` when no line qualifies.
pub fn digest(message: &Message) -> Option<String> {
    let parsed = MessageParser::new().parse(message.raw())?;
    let mut kept = Vec::new();
    for part in parsed.parts() {
        let html = match part.kind() {
            PartKind::Text => false,
            PartKind::Html => true,
            _ => continue,
        };
        let Some(text) = part.text() else { continue };
        let mut text = text.into_owned();
        let declared = part
            .content_type()
            .and_then(|c| c.attribute("charset"))
            .is_some();
        if declared {
            text.retain(|c| c != '\u{fffd}');
        } else {
            text.retain(|c| c.is_ascii());
        }
        if html {
            text = html_text(&text);
        }
        kept.extend(
            lines(&text)
                .map(normalize)
                .filter(|l| l.chars().count() >= MIN_LINE),
        );
    }
    if kept.is_empty() {
        return None;
    }
    let mut sha = Sha1::new();
    if kept.len() <= ATOMIC_LINES {
        kept.iter().for_each(|l| sha.update(l.as_bytes()));
    } else {
        for (percent, count) in PIECES {
            let start = percent * kept.len() / 100;
            for line in kept.iter().skip(start).take(count) {
                sha.update(line.as_bytes());
            }
        }
    }
    Some(hex(&sha.finalize()))
}

pub(crate) fn sha1_hex(bytes: &[u8]) -> String {
    hex(&Sha1::digest(bytes))
}

pub(crate) fn sha1_raw(bytes: &[u8]) -> [u8; 20] {
    Sha1::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_drops_volatile_parts() {
        assert_eq!(normalize("Hello  there, friend"), "Hellothere,friend");
        assert_eq!(normalize("ref 0123456789abcdef now"), "refnow");
        assert_eq!(normalize("mail ana@ex.co today"), "mailtoday");
        assert_eq!(normalize("see (ftp:xy today"), "see(today");
        assert_eq!(
            normalize("a <b>hi</b> word"),
            "a<b>hi</b>word",
            "tags stay in plain text"
        );
        assert_eq!(
            normalize("time 10:30 ok"),
            "time10:30ok",
            "digits before a colon are no scheme"
        );
    }

    fn digest_of(body: &str) -> Option<String> {
        digest(&Message::new(
            format!("Subject: x\r\n\r\n{body}").into_bytes(),
        ))
    }

    #[test]
    fn short_messages_use_every_line() {
        let expected = sha1_hex(b"Firstlinehere.Secondlinehere.");
        assert_eq!(
            digest_of("First line here.\r\nshort\r\nSecond line here.\r\n").as_deref(),
            Some(expected.as_str())
        );
        assert_eq!(digest_of("tiny\r\nlines\r\n"), None);
    }

    #[test]
    fn long_messages_use_two_windows() {
        let body: String = (0..10).map(|i| format!("line number {i}\r\n")).collect();
        let mut sha = Sha1::new();
        for i in [2, 3, 4, 6, 7, 8] {
            sha.update(format!("linenumber{i}").as_bytes());
        }
        assert_eq!(digest_of(&body), Some(hex(&sha.finalize())));
    }

    #[test]
    fn html_reduces_to_text_nodes() {
        assert_eq!(
            html_text(
                "<html><head><title>Deal</title><style>p{x}</style></head><body><p>Buy &amp; save</p>\n<!-- c --><script>var a = '<p>';</script><p>Caf&eacute; &lt;x&gt;</p></body></html>"
            ),
            "Deal Buy & save Café <x>"
        );
        assert_eq!(
            html_text("<p>one long\ntwo long</p><p>three</p>"),
            "one long\ntwo long three"
        );
        assert_eq!(html_text("a < b and <br>c"), "a < b and c");
        assert_eq!(html_text("Привет<p>мир</p>ё"), "Привет мир ё");
        assert_eq!(html_text("<p title=\"a > b\">quoted</p>"), "quoted");
        assert_eq!(
            html_text("<p>&amp chips &notit; &amp;lt; &#38;amp; &#x41;&#66 &AMP; &unknown; &</p>"),
            "& chips \u{ac}it; &lt; &amp; AB & &unknown; &"
        );
    }

    #[test]
    fn volatile_tokens_do_not_change_the_digest() {
        let a = digest_of("Dear customer ana@example.com, your code is 8f7a6b5c4d3e2f1a.\r\n");
        let b = digest_of("Dear customer bo@example.org, your code is 0000111122223333.\r\n");
        assert!(a.is_some());
        assert_eq!(a, b);
    }
}
