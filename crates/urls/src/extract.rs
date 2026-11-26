use crate::url::Url;

/// Most links taken from one piece of text or HTML.
pub const MAX_LINKS: usize = 200;

/// Where a link was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Written in plain text.
    Text,
    /// An `href`, `src` or `action` attribute.
    Attribute,
}

/// A link as found in a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// The text as written, before parsing.
    pub raw: String,
    /// The parsed URL; `None` when it does not parse.
    pub url: Option<Url>,
    /// Where it came from.
    pub source: Source,
    /// For an `<a href>`, the visible text of the anchor.
    pub anchor_text: Option<String>,
}

const SCHEMES: [&str; 4] = ["http://", "https://", "ftp://", "www."];

fn link(raw: &str, source: Source, anchor_text: Option<String>) -> Link {
    Link {
        raw: raw.to_string(),
        url: Url::parse(raw),
        source,
        anchor_text,
    }
}

/// Every `http://`, `https://`, `ftp://` and `www.` link in plain text, at most
/// [`MAX_LINKS`], in one pass over the text. A link ends at whitespace, a quote or an angle bracket; trailing punctuation
/// that usually closes a sentence is dropped.
pub fn from_text(text: &str) -> Vec<Link> {
    let lower = text.to_ascii_lowercase();
    let mut next = SCHEMES.map(|scheme| lower.find(scheme));
    let mut out = Vec::new();
    let mut at = 0;
    while out.len() < MAX_LINKS {
        for (position, scheme) in next.iter_mut().zip(SCHEMES) {
            if position.is_some_and(|p| p < at) {
                *position = lower[at..].find(scheme).map(|found| at + found);
            }
        }
        let Some(start) = next.iter().flatten().copied().min() else {
            break;
        };
        let boundary_ok = start == 0
            || !lower[..start]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || "./@".contains(c));
        let end = text[start..]
            .find(|c: char| c.is_whitespace() || "\"'<>()[]{}".contains(c))
            .map_or(text.len(), |i| start + i);
        let raw = text[start..end].trim_end_matches(['.', ',', ';', ':', '!', '?']);
        if boundary_ok && raw.len() > 4 {
            out.push(link(raw, Source::Text, None));
        }
        at = end.max(start + 1);
        while !text.is_char_boundary(at) {
            at += 1;
        }
    }
    out
}

fn attribute(attributes: &str, name: &str) -> Option<String> {
    let lower = attributes.to_ascii_lowercase();
    let mut offset = 0;
    while let Some(found) = lower[offset..].find(name) {
        let at = offset + found;
        let after = lower[at + name.len()..].trim_start();
        if (at == 0 || lower.as_bytes()[at - 1].is_ascii_whitespace())
            && let Some(value) = after.strip_prefix('=')
        {
            let start = attributes.len() - value.trim_start().len();
            let value = &attributes[start..];
            return Some(match value.chars().next() {
                Some(q @ ('"' | '\'')) => {
                    value[1..].split(q).next().unwrap_or_default().to_string()
                }
                _ => value
                    .split(char::is_whitespace)
                    .next()
                    .unwrap_or_default()
                    .to_string(),
            });
        }
        offset = at + name.len();
    }
    None
}

fn strip_tags(html: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Every link in HTML, at most [`MAX_LINKS`]: `href`, `src` and `action` attributes (with the
/// anchor text for `<a>`), then links written in the visible text outside anchors. Comments
/// are skipped.
/// Fragment-only, `mailto:`, `tel:` and `cid:` targets are not links.
pub fn from_html(html: &str) -> Vec<Link> {
    let mut out = Vec::new();
    let mut text = String::new();
    let mut in_anchor = false;
    let mut rest = html;
    while out.len() < MAX_LINKS {
        let Some(start) = rest.find('<') else {
            text.push_str(rest);
            break;
        };
        if !in_anchor {
            text.push_str(&rest[..start]);
        }
        text.push(' ');
        rest = &rest[start + 1..];
        if let Some(comment) = rest.strip_prefix("!--") {
            rest = comment.find("-->").map_or("", |end| &comment[end + 3..]);
            continue;
        }
        let end = rest.find('>').unwrap_or(rest.len());
        let tag = &rest[..end];
        rest = &rest[end.min(rest.len())..];
        rest = rest.strip_prefix('>').unwrap_or(rest);
        let closing = tag.starts_with('/');
        let tag = tag.trim_start_matches('/');
        let name_end = tag
            .find(|c: char| c.is_whitespace() || c == '/')
            .unwrap_or(tag.len());
        let name = tag[..name_end].to_ascii_lowercase();
        if name == "a" {
            in_anchor = !closing;
        }
        let attributes = if closing { "" } else { &tag[name_end..] };
        for key in ["href", "src", "action"] {
            let Some(target) = attribute(attributes, key) else {
                continue;
            };
            let target = target.trim();
            let lower = target.to_ascii_lowercase();
            if target.is_empty()
                || target.starts_with('#')
                || ["mailto:", "tel:", "cid:", "javascript:", "data:"]
                    .iter()
                    .any(|p| lower.starts_with(p))
            {
                continue;
            }
            let anchor_text = (name == "a" && key == "href").then(|| {
                let close = rest.to_ascii_lowercase().find("</a").unwrap_or(rest.len());
                strip_tags(&rest[..close])
            });
            out.push(link(target, Source::Attribute, anchor_text));
        }
    }
    let room = MAX_LINKS.saturating_sub(out.len());
    let attributes: Vec<String> = out.iter().map(|l| l.raw.to_lowercase()).collect();
    out.extend(
        from_text(&text)
            .into_iter()
            .filter(|l| !attributes.contains(&l.raw.to_lowercase()))
            .take(room),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raws(links: &[Link]) -> Vec<&str> {
        links.iter().map(|l| l.raw.as_str()).collect()
    }

    #[test]
    fn text_links() {
        let links = from_text(
            "See https://example.com/a?b=1, or www.example.org. Also (http://x.example.net/p) and mail@www.nope",
        );
        assert_eq!(
            raws(&links),
            [
                "https://example.com/a?b=1",
                "www.example.org",
                "http://x.example.net/p"
            ]
        );
        assert!(
            links
                .iter()
                .all(|l| l.url.is_some() && l.source == Source::Text)
        );
    }

    #[test]
    fn html_links_with_anchor_text() {
        let links = from_html(
            "<a href=\"https://evil.example.net/x\"><b>https://bank.example.com</b></a>\
             <img src='https://cdn.example.org/i.png'><!-- <a href=\"https://hidden.example/\"> -->\
             <a href=\"mailto:a@example.com\">mail</a><a href=\"#top\">top</a>\
             <p>Visit www.example.info today</p>",
        );
        assert_eq!(
            raws(&links),
            [
                "https://evil.example.net/x",
                "https://cdn.example.org/i.png",
                "www.example.info"
            ]
        );
        assert_eq!(
            links[0].anchor_text.as_deref(),
            Some("https://bank.example.com")
        );
        assert_eq!(links[1].anchor_text, None);
        assert_eq!(links[2].source, Source::Text);
    }

    #[test]
    fn unparsable_links_are_kept() {
        let links = from_html("<a href=\"http://bad host/\">x</a>");
        assert_eq!(links.len(), 1);
        assert!(links[0].url.is_none());
    }

    #[test]
    fn unicode_that_grows_when_lowercased_does_not_shift_positions() {
        let links = from_text(
            "\u{130}\u{130}\u{130} see https://example.com/x and \u{130} www.example.org",
        );
        let raws: Vec<&str> = links.iter().map(|l| l.raw.as_str()).collect();
        assert_eq!(raws, ["https://example.com/x", "www.example.org"]);
    }

    #[test]
    fn many_links_without_www_stay_linear() {
        let text = "https://a.example.com/ ".repeat(MAX_LINKS) + &"x".repeat(1_000_000);
        let started = std::time::Instant::now();
        assert_eq!(from_text(&text).len(), MAX_LINKS);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn bounded() {
        let text = "http://a.example.com/ ".repeat(MAX_LINKS + 20);
        assert_eq!(from_text(&text).len(), MAX_LINKS);
        let html = "<a href=\"http://a.example.com/\">x</a>".repeat(MAX_LINKS + 20);
        assert_eq!(from_html(&html).len(), MAX_LINKS);
    }

    #[test]
    fn duplicates_between_attributes_and_text_are_dropped() {
        let links = from_html("<a href=\"https://example.com/\">https://example.com/</a>");
        assert_eq!(links.len(), 1);
    }
}
