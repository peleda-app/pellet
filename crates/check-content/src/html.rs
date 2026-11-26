use async_trait::async_trait;
use mail_parser::{MessageParser, html_to_text};
use pellet_check::{Check, CheckError, Context};
use pellet_core::{Stage, Symbol, SymbolName};

use crate::mail::Symbols;

/// Most HTML looked at per part, in bytes.
const HTML_LIMIT: usize = 512 * 1024;

/// HTML parts, at [`Stage::Data`].
///
/// | Symbol | When |
/// | --- | --- |
/// | `HTML_META_REFRESH_URL` | a `<meta http-equiv="refresh">` that redirects to a URL |
/// | `EXT_CSS` | a stylesheet loaded from a remote URL |
/// | `HAS_DATA_URI` | a `data:` URI in `src` or `href` |
/// | `DATA_URI_OBFU` | a `data:` URI carrying HTML or script, or a link to one |
/// | `HTML_UNBALANCED_TAG` | `<a>`, `<div>` or `<table>` opened and closed a different number of times |
/// | `HTML_TEXT_IMG_RATIO` | images with less than 200 characters of visible text |
/// | `MANY_INVISIBLE_PARTS` | three or more elements hidden with CSS |
pub struct HtmlCheck {
    symbols: Symbols,
}

impl HtmlCheck {
    /// The check.
    pub fn new() -> Self {
        HtmlCheck {
            symbols: Symbols::new(&[
                "HTML_META_REFRESH_URL",
                "EXT_CSS",
                "HAS_DATA_URI",
                "DATA_URI_OBFU",
                "HTML_UNBALANCED_TAG",
                "HTML_TEXT_IMG_RATIO",
                "MANY_INVISIBLE_PARTS",
            ]),
        }
    }
}

impl Default for HtmlCheck {
    fn default() -> Self {
        Self::new()
    }
}

/// A tag: its lowercase name, whether it closes, and its attribute text in lowercase.
#[derive(Debug, PartialEq)]
struct Tag {
    name: String,
    closing: bool,
    attributes: String,
}

fn tags(html: &str) -> Vec<Tag> {
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut rest = lower.as_str();
    while let Some(start) = rest.find('<') {
        rest = &rest[start + 1..];
        if rest.starts_with("!--") {
            match rest.find("-->") {
                Some(end) => rest = &rest[end + 3..],
                None => break,
            }
            continue;
        }
        let end = rest.find('>').unwrap_or(rest.len());
        let inside = &rest[..end];
        rest = &rest[end.min(rest.len())..];
        let closing = inside.starts_with('/');
        let inside = inside.trim_start_matches('/');
        let name_end = inside
            .find(|c: char| c.is_whitespace() || c == '/')
            .unwrap_or(inside.len());
        let name = &inside[..name_end];
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric()) {
            continue;
        }
        out.push(Tag {
            name: name.to_string(),
            closing,
            attributes: inside[name_end..].to_string(),
        });
    }
    out
}

fn attribute<'a>(attributes: &'a str, name: &str) -> Option<&'a str> {
    let mut offset = 0;
    while let Some(found) = attributes[offset..].find(name) {
        let at = offset + found;
        let before_ok = at == 0 || attributes.as_bytes()[at - 1].is_ascii_whitespace();
        let after = attributes[at + name.len()..].trim_start();
        if before_ok && let Some(value) = after.strip_prefix('=') {
            let value = value.trim_start();
            return Some(match value.chars().next() {
                Some(q @ ('"' | '\'')) => value[1..].split(q).next().unwrap_or_default(),
                _ => value.split(char::is_whitespace).next().unwrap_or_default(),
            });
        }
        offset = at + name.len();
    }
    None
}

#[async_trait]
impl Check for HtmlCheck {
    fn name(&self) -> &str {
        "content.html"
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
        let Some(parsed) = MessageParser::new().parse(message.raw()) else {
            return Ok(Vec::new());
        };
        let mut found: Vec<&str> = Vec::new();
        for part in parsed.parts().filter(|p| p.is_content_type("text", "html")) {
            let Some(text) = part.text() else { continue };
            let mut end = text.len().min(HTML_LIMIT);
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            let html = &text[..end];
            let tags = tags(html);
            let mut emit = |name: &'static str| {
                if !found.contains(&name) {
                    found.push(name);
                }
            };

            for tag in tags.iter().filter(|t| !t.closing) {
                let a = &tag.attributes;
                if tag.name == "meta"
                    && attribute(a, "http-equiv").is_some_and(|v| v == "refresh")
                    && attribute(a, "content").is_some_and(|c| c.contains("url="))
                {
                    emit("HTML_META_REFRESH_URL");
                }
                if tag.name == "link"
                    && attribute(a, "rel").is_some_and(|r| r.contains("stylesheet"))
                    && attribute(a, "href")
                        .is_some_and(|h| h.starts_with("http") || h.starts_with("//"))
                {
                    emit("EXT_CSS");
                }
                for (key, is_link) in [("src", false), ("href", true)] {
                    if let Some(uri) =
                        attribute(a, key).filter(|v| v.trim_start().starts_with("data:"))
                    {
                        emit("HAS_DATA_URI");
                        let media = uri.trim_start()[5..]
                            .split([';', ','])
                            .next()
                            .unwrap_or_default();
                        if is_link || media.contains("html") || media.contains("script") {
                            emit("DATA_URI_OBFU");
                        }
                    }
                }
            }

            for name in ["a", "div", "table"] {
                let opened = tags.iter().filter(|t| t.name == name && !t.closing).count();
                let closed = tags.iter().filter(|t| t.name == name && t.closing).count();
                if opened != closed {
                    emit("HTML_UNBALANCED_TAG");
                }
            }

            let images = tags
                .iter()
                .filter(|t| t.name == "img" && !t.closing)
                .count();
            if images > 0 && html_to_text(html).trim().chars().count() < 200 {
                emit("HTML_TEXT_IMG_RATIO");
            }

            let hidden = tags
                .iter()
                .filter_map(|t| attribute(&t.attributes, "style"))
                .filter(|style| {
                    let style: String = style.chars().filter(|c| !c.is_whitespace()).collect();
                    style.contains("display:none")
                        || style.contains("visibility:hidden")
                        || style.contains("font-size:0")
                        || style.contains("opacity:0;")
                        || style.ends_with("opacity:0")
                })
                .count();
            if hidden >= 3 {
                emit("MANY_INVISIBLE_PARTS");
            }
        }
        Ok(found.into_iter().map(|n| self.symbols.get(n)).collect())
    }
}

#[cfg(test)]
mod tests {
    use pellet_check::testing::{Fixture, conformance};
    use pellet_core::Message;

    use super::*;

    fn message(html: &str) -> Fixture {
        let raw = format!(
            "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}\r\n"
        );
        Fixture {
            message: Some(Message::new(raw.into_bytes())),
            ..Fixture::default()
        }
    }

    const TEXT: &str = "This newsletter explains the changes to our service in plenty of detail, with several paragraphs of ordinary prose that a person would actually read, so that the visible text is comfortably longer than two hundred characters in total.";

    async fn names(html: &str) -> Vec<String> {
        let mut names: Vec<String> = HtmlCheck::new()
            .run(&message(html).context(Stage::Data))
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.name.to_string())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn tag_lexer() {
        let t = tags("<A HREF='x'>t</a><!-- <div> --><br/><p class=x>");
        let names: Vec<(&str, bool)> = t.iter().map(|t| (t.name.as_str(), t.closing)).collect();
        assert_eq!(
            names,
            [("a", false), ("a", true), ("br", false), ("p", false)]
        );
        assert_eq!(attribute(" href='x' class=y", "href"), Some("x"));
        assert_eq!(
            attribute(" data-href=\"no\" href=\"yes\"", "href"),
            Some("yes")
        );
        assert_eq!(attribute(" class=y", "href"), None);
    }

    #[tokio::test]
    async fn clean_html() {
        assert!(
            names(&format!(
                "<div><p>{TEXT}</p><a href=\"https://example.com/\">more</a></div>"
            ))
            .await
            .is_empty()
        );
    }

    #[tokio::test]
    async fn tricks() {
        assert_eq!(
            names(&format!(
                "<meta http-equiv=\"refresh\" content=\"0; url=https://example.net/\"><p>{TEXT}</p>"
            ))
            .await,
            ["HTML_META_REFRESH_URL"]
        );
        assert_eq!(
            names(&format!(
                "<link rel=\"stylesheet\" href=\"https://cdn.example.net/a.css\"><p>{TEXT}</p>"
            ))
            .await,
            ["EXT_CSS"]
        );
        assert_eq!(
            names(&format!(
                "<p>{TEXT}</p><img src=\"data:image/png;base64,AAAA\">"
            ))
            .await,
            ["HAS_DATA_URI"]
        );
        assert_eq!(
            names(&format!(
                "<p>{TEXT}</p><a href=\"data:text/html;base64,PHNjcmlwdD4=\">open</a>"
            ))
            .await,
            ["DATA_URI_OBFU", "HAS_DATA_URI"]
        );
        assert_eq!(
            names(&format!("<div><div><p>{TEXT}</p></div>")).await,
            ["HTML_UNBALANCED_TAG"]
        );
        assert_eq!(
            names("<img src=\"https://example.net/offer.png\"><p>Click</p>").await,
            ["HTML_TEXT_IMG_RATIO"]
        );
        let hidden = "<span style=\"display: none\">a</span>".repeat(2)
            + "<span style=\"font-size:0\">b</span>";
        assert_eq!(
            names(&format!("<p>{TEXT}</p>{hidden}")).await,
            ["MANY_INVISIBLE_PARTS"]
        );
    }

    #[tokio::test]
    async fn passes_conformance() {
        conformance(
            &HtmlCheck::new(),
            &[
                message("<meta http-equiv=refresh content=\"0;url=x\"><img src=\"data:text/html,x\"><div>"),
                message(TEXT),
                Fixture::message(""),
            ],
        )
        .await;
    }
}
