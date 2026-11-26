/// Changes whenever tokens change; a model trained with another version is refused.
pub const TOKENIZER_VERSION: u32 = 1;

/// Most tokens taken from one document.
pub const MAX_TOKENS: usize = 4000;

/// What the classifier looks at in a message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Document {
    /// The decoded subject.
    pub subject: String,
    /// The visible body text.
    pub body: String,
    /// Domains of the links.
    pub domains: Vec<String>,
    /// The domain of the From address.
    pub sender_domain: String,
    /// Names of the header fields present.
    pub headers: Vec<String>,
    /// Symbols other checks emitted.
    pub symbols: Vec<String>,
}

fn words(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty() && w.chars().count() <= 32)
        .map(|w| {
            if w.chars().all(|c| c.is_ascii_digit()) {
                format!("<{}>", w.len().min(6))
            } else {
                w.to_lowercase()
            }
        })
}

/// The tokens of a document, each prefixed with its kind: `s:` subject words, `w:` body words,
/// `b:` pairs of body words, `d:` link domains, `f:` the sender domain, `h:` header names,
/// `y:` symbols. Digit runs become `<length>`. At most [`MAX_TOKENS`], duplicates kept out.
pub fn tokens(doc: &Document) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut push = |token: String, out: &mut Vec<String>| {
        if out.len() < MAX_TOKENS && seen.insert(token.clone()) {
            out.push(token);
        }
    };
    for word in words(&doc.subject) {
        push(format!("s:{word}"), &mut out);
    }
    let body: Vec<String> = words(&doc.body).collect();
    for word in &body {
        push(format!("w:{word}"), &mut out);
    }
    for pair in body.windows(2) {
        push(format!("b:{} {}", pair[0], pair[1]), &mut out);
    }
    for domain in &doc.domains {
        push(format!("d:{}", domain.to_lowercase()), &mut out);
    }
    if !doc.sender_domain.is_empty() {
        push(format!("f:{}", doc.sender_domain.to_lowercase()), &mut out);
    }
    for header in &doc.headers {
        push(format!("h:{}", header.to_lowercase()), &mut out);
    }
    for symbol in &doc.symbols {
        push(format!("y:{symbol}"), &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_and_normalization() {
        let doc = Document {
            subject: "Win BIG".into(),
            body: "Call 555123 now, call now".into(),
            domains: vec!["Offer.Example.net".into()],
            sender_domain: "example.net".into(),
            headers: vec!["X-Mailer".into()],
            symbols: vec!["RBL_EXAMPLE".into()],
        };
        assert_eq!(
            tokens(&doc),
            [
                "s:win",
                "s:big",
                "w:call",
                "w:<6>",
                "w:now",
                "b:call <6>",
                "b:<6> now",
                "b:now call",
                "b:call now",
                "d:offer.example.net",
                "f:example.net",
                "h:x-mailer",
                "y:RBL_EXAMPLE",
            ]
        );
    }

    #[test]
    fn bounded_and_unicode() {
        let doc = Document {
            body: (0..10_000).map(|i| format!("w{i} ")).collect(),
            ..Document::default()
        };
        assert_eq!(tokens(&doc).len(), MAX_TOKENS);
        let doc = Document {
            body: "Привет мир".into(),
            ..Document::default()
        };
        assert_eq!(tokens(&doc)[0], "w:привет");
    }
}
