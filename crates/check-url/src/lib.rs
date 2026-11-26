//! URL extraction, redirector unwrapping and phishing heuristics.

use std::collections::HashSet;

use async_trait::async_trait;
use pellet_check::{Check, CheckError, Context, symbol_names};
use pellet_core::{Stage, Symbol, SymbolName};
use pellet_urls::{Source, Url, message_links};

const SYMBOLS: [&str; 15] = [
    "URL_ONLY",
    "BODY_URI_ONLY",
    "URL_IN_SUBJECT",
    "HTTP_TO_IP",
    "HTTP_TO_HTTPS",
    "SUSPICIOUS_URL",
    "PHISHING",
    "HOMOGRAPH_URL",
    "MIXED_CHARSET_URL",
    "ZERO_WIDTH_SPACE_URL",
    "UNPARSABLE_URL",
    "URI_COUNT_ODD",
    "REDIRECTOR_URL",
    "URL_REDIRECTOR_INSECURE",
    "URL_REDIRECTOR_NESTED",
];

/// The links of a message, at [`Stage::Data`].
///
/// | Symbol | When |
/// | --- | --- |
/// | `URL_ONLY`, `BODY_URI_ONLY` | a plain text part, or an HTML part, with almost nothing but links |
/// | `URL_IN_SUBJECT` | the subject holds a link |
/// | `HTTP_TO_IP` | a link to an IP address |
/// | `SUSPICIOUS_URL` | a link with a user name before `@`, or a host written as a number |
/// | `HTTP_TO_HTTPS` | an anchor shows an `https` address but links over `http` |
/// | `PHISHING` | an anchor shows a domain under a known public suffix and links to another (after unwrapping redirectors; not when a redirector or a click tracker from [`UrlCheck::click_trackers`] hides where it leads); option: the shown domain |
/// | `HOMOGRAPH_URL` | a host label mixing Latin (with its accented letters) with Cyrillic, Greek or other letters |
/// | `MIXED_CHARSET_URL` | a host with labels in different scripts |
/// | `ZERO_WIDTH_SPACE_URL` | a link with zero-width characters |
/// | `UNPARSABLE_URL` | a link target that does not parse |
/// | `URI_COUNT_ODD` | a message with plain and HTML parts and an odd number of distinct links |
/// | `REDIRECTOR_URL`, `URL_REDIRECTOR_INSECURE`, `URL_REDIRECTOR_NESTED` | a link through a known redirector; over `http`; to another redirector |
pub struct UrlCheck {
    declared: Vec<SymbolName>,
    redirectors: HashSet<String>,
    click_trackers: HashSet<String>,
}

fn host_set<S: AsRef<str>>(hosts: impl IntoIterator<Item = S>) -> HashSet<String> {
    hosts
        .into_iter()
        .map(|r| r.as_ref().trim().to_lowercase())
        .filter(|r| !r.is_empty())
        .collect()
}

impl UrlCheck {
    /// The check with the known redirector hosts (the bundled `url-redirectors` list).
    pub fn new<S: AsRef<str>>(redirectors: impl IntoIterator<Item = S>) -> Self {
        UrlCheck {
            declared: symbol_names(&SYMBOLS),
            redirectors: host_set(redirectors),
            click_trackers: HashSet::new(),
        }
    }

    /// Click-tracking hosts of mail delivery services (the bundled `click-trackers` list),
    /// matched by host or any parent domain. Their links hide where they lead, so a link that
    /// ends at one is never `PHISHING`; they make no other symbol.
    pub fn click_trackers<S: AsRef<str>>(mut self, hosts: impl IntoIterator<Item = S>) -> Self {
        self.click_trackers = host_set(hosts);
        self
    }

    fn is_opaque(&self, url: &Url) -> bool {
        self.is_redirector(url)
            || std::iter::successors(Some(url.host.as_str()), |h| {
                h.split_once('.').map(|(_, rest)| rest)
            })
            .any(|h| self.click_trackers.contains(h))
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

    fn is_redirector(&self, url: &Url) -> bool {
        self.redirectors.contains(&url.host) || self.redirectors.contains(url.registrable())
    }

    fn destination(&self, url: &Url) -> Url {
        let mut current = url.clone();
        for _ in 0..5 {
            match self
                .is_redirector(&current)
                .then(|| current.redirect_target())
                .flatten()
            {
                Some(next) => current = next,
                None => break,
            }
        }
        current
    }
}

fn script(c: char) -> Option<u8> {
    match c {
        'a'..='z'
        | 'A'..='Z'
        | '\u{00C0}'..='\u{00D6}'
        | '\u{00D8}'..='\u{00F6}'
        | '\u{00F8}'..='\u{024F}'
        | '\u{1E00}'..='\u{1EFF}'
        | '\u{2C60}'..='\u{2C7F}'
        | '\u{A720}'..='\u{A7FF}'
        | '\u{AB30}'..='\u{AB6F}' => Some(0),
        '\u{0400}'..='\u{052F}'
        | '\u{1C80}'..='\u{1C8F}'
        | '\u{2DE0}'..='\u{2DFF}'
        | '\u{A640}'..='\u{A69F}' => Some(1),
        '\u{0370}'..='\u{03FF}' | '\u{1F00}'..='\u{1FFF}' => Some(2),
        c if c.is_alphabetic() => Some(3),
        _ => None,
    }
}

fn scripts(text: &str) -> HashSet<u8> {
    text.chars().filter_map(script).collect()
}

/// File extensions that are also top-level domains, read as file names when shown bare.
const FILE_NAME_SUFFIXES: [&str; 5] = ["md", "pl", "py", "rs", "sh"];

/// A domain shown as text, such as `https://bank.example.com` or `bank.example.com`.
fn shown_url(text: &str) -> Option<Url> {
    let text = text.trim();
    if text.is_empty() || text.contains(char::is_whitespace) || !text.contains('.') {
        return None;
    }
    let bare = !text.contains("://");
    if bare && text.contains('@') {
        return None;
    }
    let url = Url::parse(text).or_else(|| Url::parse(&format!("http://{text}")))?;
    if !url.has_known_suffix() {
        return None;
    }
    let file_name = bare
        && !url.host.starts_with("www.")
        && url.host.matches('.').count() == 1
        && url
            .host
            .rsplit('.')
            .next()
            .is_some_and(|tld| FILE_NAME_SUFFIXES.contains(&tld));
    (!file_name).then_some(url)
}

#[async_trait]
impl Check for UrlCheck {
    fn name(&self) -> &str {
        "url"
    }

    fn stage(&self) -> Stage {
        Stage::Data
    }

    fn symbols(&self) -> &[SymbolName] {
        &self.declared
    }

    async fn run(&self, ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError> {
        let message = ctx
            .message
            .ok_or_else(|| CheckError::Failed("no message at the data stage".into()))?;
        let view = message_links(message);
        let plain_only_links = view
            .parts
            .iter()
            .any(|p| !p.html && !p.links.is_empty() && p.leftover < 10);
        let html_only_links = view
            .parts
            .iter()
            .any(|p| p.html && p.links.iter().any(|l| l.anchor_text.is_some()) && p.leftover < 10);
        let mut out: Vec<Symbol> = Vec::new();
        let mut emit = |symbol: Symbol| match out.iter_mut().find(|s| s.name == symbol.name) {
            Some(existing) => {
                for option in symbol.options {
                    if !existing.options.contains(&option) {
                        existing.push_option(option);
                    }
                }
            }
            None => out.push(symbol),
        };

        if plain_only_links {
            emit(self.symbol("URL_ONLY"));
        }
        if html_only_links {
            emit(self.symbol("BODY_URI_ONLY"));
        }
        if !view.subject.is_empty() {
            emit(self.symbol("URL_IN_SUBJECT"));
        }
        let distinct: HashSet<String> = view.links().map(|l| l.raw.to_lowercase()).collect();
        if view.alternative && distinct.len() % 2 == 1 {
            emit(self.symbol("URI_COUNT_ODD"));
        }

        for link in view.links() {
            if link
                .raw
                .chars()
                .any(|c| matches!(c, '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}'))
            {
                emit(self.symbol("ZERO_WIDTH_SPACE_URL"));
            }
            let Some(url) = &link.url else {
                if link.source == Source::Attribute {
                    emit(self.symbol("UNPARSABLE_URL"));
                }
                continue;
            };
            let web = matches!(url.scheme.as_str(), "http" | "https");
            if web && url.host_ip().is_some() {
                emit(self.symbol("HTTP_TO_IP"));
            }
            if url.userinfo.is_some() || url.host_is_numeric() {
                emit(self.symbol("SUSPICIOUS_URL"));
            }
            for label in url.host.split('.') {
                if scripts(label).len() > 1 {
                    emit(self.symbol("HOMOGRAPH_URL"));
                }
            }
            let label_scripts: HashSet<Vec<u8>> = url
                .host
                .split('.')
                .map(|l| {
                    let mut s: Vec<u8> = scripts(l).into_iter().collect();
                    s.sort();
                    s
                })
                .filter(|s| !s.is_empty())
                .collect();
            if !url.host.is_ascii() && label_scripts.len() > 1 {
                emit(self.symbol("MIXED_CHARSET_URL"));
            }
            if self.is_redirector(url) {
                emit(self.symbol("REDIRECTOR_URL").with_option(url.host.clone()));
                if url.scheme == "http" {
                    emit(self.symbol("URL_REDIRECTOR_INSECURE"));
                }
                if url
                    .redirect_target()
                    .is_some_and(|t| self.is_redirector(&t))
                {
                    emit(self.symbol("URL_REDIRECTOR_NESTED"));
                }
            }
            if let Some(shown) = link.anchor_text.as_deref().and_then(shown_url) {
                if shown.scheme == "https"
                    && url.scheme == "http"
                    && link
                        .anchor_text
                        .as_deref()
                        .is_some_and(|t| t.trim().to_lowercase().starts_with("https://"))
                {
                    emit(self.symbol("HTTP_TO_HTTPS"));
                }
                let target = self.destination(url);
                if web && !self.is_opaque(&target) && shown.registrable() != target.registrable() {
                    emit(
                        self.symbol("PHISHING")
                            .with_option(shown.registrable().to_string()),
                    );
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
