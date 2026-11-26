use std::sync::Arc;

use mail_parser::{MessageParser, html_to_text};
use pellet_core::Message;

use crate::{Link, MAX_LINKS, Source, Url, from_html, from_text};

/// The links of one text or HTML part.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PartLinks {
    /// Whether the part is HTML.
    pub html: bool,
    /// Its links, in order.
    pub links: Vec<Link>,
    /// Characters of its visible text, whitespace aside, that are neither a written link nor an
    /// anchor's text.
    pub leftover: usize,
}

/// Every link of a message, found once and shared by the checks that need them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MessageLinks {
    /// The plain and HTML parts, in document order.
    pub parts: Vec<PartLinks>,
    /// Links written in the subject.
    pub subject: Vec<Link>,
    /// Whether the message has both a plain and an HTML part.
    pub alternative: bool,
}

impl MessageLinks {
    /// Every link of every part, in order.
    pub fn links(&self) -> impl Iterator<Item = &Link> {
        self.parts.iter().flat_map(|p| &p.links)
    }

    /// The distinct parsed URLs, in order of first appearance, at most [`MAX_LINKS`].
    pub fn urls(&self) -> Vec<&Url> {
        let mut out: Vec<&Url> = Vec::new();
        for url in self.links().filter_map(|l| l.url.as_ref()) {
            if out.len() >= MAX_LINKS {
                break;
            }
            if !out.contains(&url) {
                out.push(url);
            }
        }
        out
    }
}

fn solid(text: &str) -> usize {
    text.chars().filter(|c| !c.is_whitespace()).count()
}

/// Characters of the visible text, whitespace aside, minus those of written links and anchor
/// texts, never below zero. Attribute targets are not visible, so they take nothing away.
pub fn leftover(visible: &str, links: &[Link]) -> usize {
    let taken: usize = links
        .iter()
        .map(|l| {
            let written = if l.source == Source::Text {
                solid(&l.raw)
            } else {
                0
            };
            written + l.anchor_text.as_deref().map_or(0, solid)
        })
        .sum();
    solid(visible).saturating_sub(taken)
}

fn build(message: &Message) -> MessageLinks {
    let mut view = MessageLinks::default();
    let Some(parsed) = MessageParser::new().parse(message.raw()) else {
        return view;
    };
    view.subject = parsed.subject().map(from_text).unwrap_or_default();
    let (mut plain, mut html) = (false, false);
    for part in parsed.parts() {
        let is_html = part.is_content_type("text", "html");
        if !is_html && !part.is_content_type("text", "plain") {
            continue;
        }
        let Some(text) = part.text() else { continue };
        let (links, visible) = if is_html {
            (from_html(&text), html_to_text(&text))
        } else {
            (from_text(&text), text.into_owned())
        };
        plain |= !is_html;
        html |= is_html;
        view.parts.push(PartLinks {
            html: is_html,
            leftover: leftover(&visible, &links),
            links,
        });
    }
    view.alternative = plain && html;
    view
}

/// The links of a message, found on the first call and cached on the message for every later
/// one.
pub fn message_links(message: &Message) -> Arc<MessageLinks> {
    message.cached(build)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: &str = "Subject: see www.offer.example.net\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nRead https://example.com/a now\r\n--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Read <a href=\"https://example.com/a\">the report</a> and <a href=\"https://example.com/b\">more</a></p>\r\n--b--\r\n";

    #[test]
    fn finds_links_per_part_once() {
        let message = Message::new(RAW.as_bytes());
        let view = message_links(&message);
        assert!(view.alternative);
        assert_eq!(view.subject.len(), 1);
        assert_eq!(view.parts.len(), 2);
        assert!(!view.parts[0].html && view.parts[1].html);
        assert_eq!(view.parts[0].leftover, "Readnow".len());
        assert_eq!(view.links().count(), 3);
        let urls: Vec<&str> = view.urls().iter().map(|u| u.raw.as_str()).collect();
        assert_eq!(urls, ["https://example.com/a", "https://example.com/b"]);
        assert!(
            Arc::ptr_eq(&view, &message_links(&message.clone())),
            "cached"
        );
    }

    #[test]
    fn leftover_ignores_invisible_targets() {
        let links = from_html("<a href=\"https://very.long.example.com/path/to/somewhere\">x</a>");
        assert_eq!(leftover("hello x", &links), "hello".len());
    }

    #[test]
    fn unparsable_messages_have_no_links() {
        assert_eq!(
            *message_links(&Message::new(Vec::new())),
            MessageLinks::default()
        );
    }
}
