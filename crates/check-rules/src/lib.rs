//! Checks defined as data in `pellet-rules`, including composites over other symbols, and the
//! DNS lists the data defines.

mod dnsbl;

pub use dnsbl::{DnsListCheck, MAX_QUERIES};

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use async_trait::async_trait;
use mail_parser::MessageParser;
use pellet_check::{Check, CheckError, Context};
use pellet_core::{Envelope, Header, Message, Stage, Symbol, SymbolName};
use pellet_rules::{Env, Lists, RuleSet, Scope, Value};
use pellet_urls::{Url, message_links};

/// Most body text the `body` variable holds.
const BODY_LIMIT: usize = 64 * 1024;

/// Scopes this check evaluates; `domain` and `ip` belong to DNS lists.
const SCOPES: [Scope; 4] = [Scope::Any, Scope::Header, Scope::Email, Scope::Url];

/// Rules from data, at [`Stage::Data`], after every other check of the stage.
///
/// Rules run one by one in priority order. `any` rules run once, `header` rules once per
/// top-level header field, `email` rules once per address (`env_from`, `env_to` from the
/// envelope; `from`, `reply_to`, `to`, `cc`, `bcc` from the headers), `url` rules once per
/// distinct link in the text and HTML parts. A rule sees every symbol
/// emitted so far, including those of rules before it. A rule result that names a symbol the
/// rule set declares emits it once; anything else emits nothing.
///
/// Variables: `subject` (decoded), `from` and `reply_to` (first mailbox: `name`, `local`,
/// `domain`, `email`, `sld`), `env_from` (the same, `null` for the null sender), `body` (the first
/// text part, at most 64 KiB); header rules add `name`, `name_lower`, `value`, `value_lower`,
/// `raw`, `raw_lower`; email rules add `email`, `name`, `local`, `domain`, `sld`, `location`;
/// url rules add `url`, `scheme`, `host`, `path` and `path_query` (lowercased), `sld`.
pub struct RulesCheck {
    rules: Arc<RuleSet>,
    declared: Vec<SymbolName>,
}

impl RulesCheck {
    /// Builds the check over a rule set.
    pub fn new(rules: Arc<RuleSet>) -> Self {
        let declared = rules.symbols(&SCOPES).into_iter().collect();
        RulesCheck { rules, declared }
    }
}

pub(crate) struct RuleEnv<'a> {
    pub(crate) message: HashMap<&'static str, Value>,
    pub(crate) scoped: HashMap<&'static str, Value>,
    pub(crate) symbols: HashSet<String>,
    pub(crate) lists: &'a Lists,
}

impl Env for RuleEnv<'_> {
    fn var(&self, name: &str) -> Value {
        self.scoped
            .get(name)
            .or_else(|| self.message.get(name))
            .cloned()
            .unwrap_or_default()
    }

    fn symbol(&self, name: &str) -> bool {
        self.symbols.contains(name)
    }

    fn list_contains(&self, list: &str, key: &str) -> bool {
        self.lists.contains(list, key)
    }
}

fn address(name: Option<&str>, email: &str) -> Value {
    let email = email.trim().to_lowercase();
    let (local, domain) = email.rsplit_once('@').unwrap_or((email.as_str(), ""));
    let mut fields = BTreeMap::new();
    fields.insert(
        "name".to_string(),
        Value::from(name.unwrap_or_default().trim()),
    );
    fields.insert("local".to_string(), Value::from(local));
    fields.insert("domain".to_string(), Value::from(domain));
    fields.insert(
        "sld".to_string(),
        Value::from(psl::domain_str(domain).unwrap_or_default()),
    );
    fields.insert("email".to_string(), Value::from(email.as_str()));
    Value::Map(fields)
}

pub(crate) struct Parsed {
    pub(crate) message: HashMap<&'static str, Value>,
    pub(crate) addresses: Vec<(&'static str, Value)>,
    pub(crate) urls: Vec<Url>,
}

pub(crate) fn parse(message: &Message, envelope: &Envelope) -> Parsed {
    let raw = message.raw();
    let urls: Vec<Url> = message_links(message).urls().into_iter().cloned().collect();

    let mut message = HashMap::new();
    let mut addresses = Vec::new();

    let env_from = match envelope.mail_from.as_deref() {
        Some(sender) if !sender.is_empty() => address(None, sender),
        _ => Value::Null,
    };
    if !matches!(env_from, Value::Null) {
        addresses.push(("env_from", env_from.clone()));
    }
    message.insert("env_from", env_from);
    for rcpt in &envelope.recipients {
        addresses.push(("env_to", address(None, rcpt)));
    }

    let parsed = MessageParser::new().parse(raw);
    let subject = parsed
        .as_ref()
        .and_then(|m| m.subject())
        .unwrap_or_default()
        .to_string();
    message.insert("subject", Value::Str(subject));
    let mut body = parsed
        .as_ref()
        .and_then(|m| m.body_text(0))
        .map(|b| b.into_owned())
        .unwrap_or_default();
    if body.len() > BODY_LIMIT {
        let mut end = BODY_LIMIT;
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        body.truncate(end);
    }
    message.insert("body", Value::Str(body));
    let mut first = |key: &'static str, list: Option<mail_parser::AddressList<'_>>| {
        let mailboxes: Vec<Value> = list
            .map(|l| {
                l.mailboxes()
                    .filter_map(|m| Some(address(m.name(), m.address()?)))
                    .collect()
            })
            .unwrap_or_default();
        message.insert(key, mailboxes.first().cloned().unwrap_or_default());
        for mailbox in mailboxes {
            addresses.push((key, mailbox));
        }
    };
    if let Some(m) = &parsed {
        first("from", m.from());
        first("reply_to", m.reply_to());
        let mut rest = |key: &'static str, list: Option<mail_parser::AddressList<'_>>| {
            if let Some(list) = list {
                for m in list.mailboxes() {
                    if let Some(email) = m.address() {
                        addresses.push((key, address(m.name(), email)));
                    }
                }
            }
        };
        rest("to", m.to());
        rest("cc", m.cc());
        rest("bcc", m.bcc());
    } else {
        message.insert("from", Value::Null);
        message.insert("reply_to", Value::Null);
    }
    Parsed {
        message,
        addresses,
        urls,
    }
}

fn header_vars(header: &Header) -> HashMap<&'static str, Value> {
    let value = header.value_str().into_owned();
    let raw = format!("{}: {value}", header.name());
    HashMap::from([
        ("name", Value::from(header.name())),
        (
            "name_lower",
            Value::from(header.name().to_ascii_lowercase()),
        ),
        ("value_lower", Value::from(value.to_lowercase())),
        ("value", Value::Str(value)),
        ("raw_lower", Value::from(raw.to_lowercase())),
        ("raw", Value::Str(raw)),
    ])
}

fn url_vars(url: &Url) -> HashMap<&'static str, Value> {
    HashMap::from([
        ("url", Value::from(url.raw.as_str())),
        ("scheme", Value::from(url.scheme.as_str())),
        ("host", Value::from(url.host.as_str())),
        ("path", Value::from(url.path.to_lowercase())),
        ("path_query", Value::from(url.path_query().to_lowercase())),
        ("sld", Value::from(url.registrable())),
    ])
}

fn email_vars(location: &'static str, address: &Value) -> HashMap<&'static str, Value> {
    let mut vars = HashMap::from([("location", Value::from(location))]);
    for key in ["email", "name", "local", "domain", "sld"] {
        let field: &'static str = key;
        vars.insert(field, address.field(key));
    }
    vars
}

#[async_trait]
impl Check for RulesCheck {
    fn name(&self) -> &str {
        "rules"
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
        let parsed = parse(message, ctx.envelope);
        let mut env = RuleEnv {
            message: parsed.message,
            scoped: HashMap::new(),
            symbols: ctx.earlier.iter().map(|s| s.name.to_string()).collect(),
            lists: self.rules.lists(),
        };
        let mut out: Vec<Symbol> = Vec::new();
        let mut emit = |env: &mut RuleEnv<'_>, result: Value| {
            let Value::Str(name) = result else { return };
            if let Some(declared) = self.declared.iter().find(|d| d.as_str() == name) {
                if !out.iter().any(|s| &s.name == declared) {
                    out.push(Symbol::new(declared.clone()));
                }
                env.symbols.insert(name);
            }
        };

        for rule in self.rules.rules() {
            match rule.scope {
                Scope::Any => {
                    env.scoped.clear();
                    let result = rule.condition.eval(&env);
                    emit(&mut env, result);
                }
                Scope::Header => {
                    for header in message.headers() {
                        env.scoped = header_vars(header);
                        let result = rule.condition.eval(&env);
                        emit(&mut env, result);
                    }
                }
                Scope::Email => {
                    for (location, address) in &parsed.addresses {
                        env.scoped = email_vars(location, address);
                        let result = rule.condition.eval(&env);
                        emit(&mut env, result);
                    }
                }
                Scope::Url => {
                    for url in &parsed.urls {
                        env.scoped = url_vars(url);
                        let result = rule.condition.eval(&env);
                        emit(&mut env, result);
                    }
                }
                Scope::Domain | Scope::Ip => {}
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
