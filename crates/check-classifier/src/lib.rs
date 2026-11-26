//! The classifier as a check, plus learning from user feedback and strong signals.

use std::sync::{
    Arc, RwLock,
    atomic::{AtomicU64, Ordering},
};

use async_trait::async_trait;
use mail_parser::{MessageParser, html_to_text};
use pellet_check::{Check, CheckError, Context, symbol_names};
use pellet_classifier::{Document, Model};
use pellet_core::{Envelope, Message, Stage, Symbol, SymbolName};
use pellet_urls::message_links;

/// Most body text the classifier reads, in bytes.
const BODY_LIMIT: usize = 64 * 1024;

const SYMBOLS: [&str; 7] = [
    "PROB_SPAM_HIGH",
    "PROB_SPAM_MEDIUM",
    "PROB_SPAM_LOW",
    "PROB_SPAM_UNCERTAIN",
    "PROB_HAM_LOW",
    "PROB_HAM_MEDIUM",
    "PROB_HAM_HIGH",
];

/// When the classifier speaks and what it learns from by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifierConfig {
    /// Ham samples the model needs before it emits anything.
    pub min_ham: u64,
    /// Spam samples the model needs before it emits anything.
    pub min_spam: u64,
    /// Whether strong signals train the model without a person marking the message.
    pub auto_learn: bool,
    /// Symbol name prefixes that count as blocklist hits for auto-learning.
    pub blocklists: Vec<String>,
}

impl Default for ClassifierConfig {
    fn default() -> Self {
        ClassifierConfig {
            min_ham: 50,
            min_spam: 50,
            auto_learn: true,
            blocklists: [
                "RBL_",
                "RECEIVED_",
                "DBL_",
                "SURBL_",
                "URIBL_",
                "MSBL_",
                "SEM_URIBL",
            ]
            .map(String::from)
            .to_vec(),
        }
    }
}

/// The classifier at [`Stage::Data`], after the other checks of the stage, so their symbols are
/// features too.
///
/// | Symbol | Probability of spam |
/// | --- | --- |
/// | `PROB_SPAM_HIGH` | 0.95 and above |
/// | `PROB_SPAM_MEDIUM` | 0.80 to 0.95 |
/// | `PROB_SPAM_LOW` | 0.60 to 0.80 |
/// | `PROB_SPAM_UNCERTAIN` | 0.40 to 0.60 |
/// | `PROB_HAM_LOW` | 0.20 to 0.40 |
/// | `PROB_HAM_MEDIUM` | 0.05 to 0.20 |
/// | `PROB_HAM_HIGH` | below 0.05 |
///
/// The option is the probability with two decimals. Nothing is emitted until the model has
/// [`ClassifierConfig::min_ham`] and [`ClassifierConfig::min_spam`] samples.
///
/// With auto-learning, an unauthenticated message is learned as spam when it has a blocklist hit
/// together with `DMARC_POLICY_REJECT`, `DMARC_POLICY_QUARANTINE` or `SPF_FAIL`, or when it is
/// `GTUBE_TEST` or `SPAM_TRAP`; and as ham when `DKIM_ALLOW`, `SPF_ALLOW` and `DMARC_POLICY_ALLOW` all fired
/// without a blocklist hit. The model lives in memory; [`ClassifierCheck::snapshot`] hands it to
/// the host to keep.
pub struct ClassifierCheck {
    model: Arc<RwLock<Model>>,
    config: ClassifierConfig,
    declared: Vec<SymbolName>,
    updates: AtomicU64,
}

impl ClassifierCheck {
    /// The check over a model, trained or not.
    pub fn new(model: Model, config: ClassifierConfig) -> Self {
        ClassifierCheck {
            model: Arc::new(RwLock::new(model)),
            config,
            declared: symbol_names(&SYMBOLS),
            updates: AtomicU64::new(0),
        }
    }

    /// Learns a message a person marked, with the symbols the other checks gave it.
    pub fn learn(&self, message: &Message, envelope: &Envelope, symbols: &[Symbol], spam: bool) {
        let doc = document(message, envelope, symbols);
        self.model
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .train(&doc, spam);
        self.updates.fetch_add(1, Ordering::Relaxed);
    }

    /// Samples the model holds, as (ham, spam), without copying it.
    pub fn samples(&self) -> (u64, u64) {
        self.model
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .samples()
    }

    /// A copy of the model as it is now.
    pub fn snapshot(&self) -> Model {
        self.model.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Samples learned through this check since it was built, by feedback or automatically.
    pub fn updates(&self) -> u64 {
        self.updates.load(Ordering::Relaxed)
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

    fn auto_label(&self, ctx: &Context<'_>) -> Option<bool> {
        if !self.config.auto_learn || ctx.envelope.authenticated {
            return None;
        }
        let blocklisted = ctx.earlier.iter().any(|s| {
            self.config
                .blocklists
                .iter()
                .any(|prefix| s.name.as_str().starts_with(prefix.as_str()))
        });
        let failed = ["DMARC_POLICY_REJECT", "DMARC_POLICY_QUARANTINE", "SPF_FAIL"]
            .iter()
            .any(|n| ctx.earlier_has(n));
        if ctx.earlier_has("GTUBE_TEST") || ctx.earlier_has("SPAM_TRAP") || (blocklisted && failed)
        {
            return Some(true);
        }
        let authenticated = ["DKIM_ALLOW", "SPF_ALLOW", "DMARC_POLICY_ALLOW"]
            .iter()
            .all(|n| ctx.earlier_has(n));
        (authenticated && !blocklisted).then_some(false)
    }
}

/// What the classifier reads from a message: the decoded subject, the visible text of the first
/// text or HTML body, link domains, the From domain, header names and the other checks' symbols
/// (classifier symbols left out).
pub fn document(message: &Message, envelope: &Envelope, symbols: &[Symbol]) -> Document {
    let mut doc = Document {
        headers: message
            .headers()
            .iter()
            .map(|h| h.name().to_string())
            .collect(),
        symbols: symbols
            .iter()
            .map(|s| s.name.to_string())
            .filter(|n| !n.starts_with("PROB_"))
            .collect(),
        ..Document::default()
    };
    if let Some(sender) = envelope.mail_from.as_deref()
        && let Some((_, domain)) = sender.rsplit_once('@')
    {
        doc.sender_domain = domain.to_lowercase();
    }
    let Some(parsed) = MessageParser::new().parse(message.raw()) else {
        return doc;
    };
    doc.subject = parsed.subject().unwrap_or_default().to_string();
    if let Some(from) = parsed.from().and_then(|f| f.first())
        && let Some((_, domain)) = from.address().and_then(|a| a.rsplit_once('@'))
    {
        doc.sender_domain = domain.to_lowercase();
    }
    let first = parsed
        .parts()
        .find(|p| p.is_content_type("text", "plain") || p.is_content_type("text", "html"));
    if let Some(part) = first
        && let Some(text) = part.text()
    {
        doc.body = if part.is_content_type("text", "html") {
            html_to_text(&text)
        } else {
            text.into_owned()
        };
    }
    if doc.body.len() > BODY_LIMIT {
        let mut end = BODY_LIMIT;
        while !doc.body.is_char_boundary(end) {
            end -= 1;
        }
        doc.body.truncate(end);
    }
    for url in message_links(message).urls() {
        let domain = url.registrable().to_string();
        if !doc.domains.contains(&domain) {
            doc.domains.push(domain);
        }
    }
    doc
}

fn band(p: f64) -> &'static str {
    match p {
        p if p >= 0.95 => "PROB_SPAM_HIGH",
        p if p >= 0.80 => "PROB_SPAM_MEDIUM",
        p if p >= 0.60 => "PROB_SPAM_LOW",
        p if p > 0.40 => "PROB_SPAM_UNCERTAIN",
        p if p > 0.20 => "PROB_HAM_LOW",
        p if p > 0.05 => "PROB_HAM_MEDIUM",
        _ => "PROB_HAM_HIGH",
    }
}

#[async_trait]
impl Check for ClassifierCheck {
    fn name(&self) -> &str {
        "classifier"
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
        let message = ctx
            .message
            .ok_or_else(|| CheckError::Failed("no message at the data stage".into()))?;
        let doc = document(message, ctx.envelope, ctx.earlier);
        let mut out = Vec::new();
        {
            let model = self.model.read().unwrap_or_else(|p| p.into_inner());
            let (ham, spam) = model.samples();
            if ham >= self.config.min_ham && spam >= self.config.min_spam {
                let p = model.predict(&doc);
                out.push(self.symbol(band(p)).with_option(format!("{p:.2}")));
            }
        }
        if let Some(spam) = self.auto_label(ctx) {
            self.model
                .write()
                .unwrap_or_else(|p| p.into_inner())
                .train(&doc, spam);
            self.updates.fetch_add(1, Ordering::Relaxed);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
