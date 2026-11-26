use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
};

use async_trait::async_trait;
use futures::future::join_all;
use pellet_check::{Check, CheckError, Context};
use pellet_core::{Message, Stage, Symbol, SymbolName};
use pellet_dns::{Resolver, is_listable, list_query, normalize};
use pellet_rules::{RuleSet, Scope, Value};

use crate::{RuleEnv, parse};

/// Most DNS queries one message may cause.
pub const MAX_QUERIES: usize = 64;

/// The DNS lists defined in the rule data (`[dnsbl.*]`), at [`Stage::Data`], after the other
/// checks of the stage.
///
/// Every list's `zone` is evaluated for every item of its scope; a string result is the name to
/// query, `false` skips the item. Every A record of the answer is fed to `tag` as `octets`; a
/// string result names the symbol to emit, if the data declares it.
///
/// | Scope | Items | Variables |
/// | --- | --- | --- |
/// | `ip` | the client (`location` `tcp`) and the addresses in `Received` fields (`received`), public ones only | `ip`, `ip_reverse`, `is_v4`, `is_v6`, `location` |
/// | `domain` | registrable domains of the links (`url`), From (`from`), Reply-To (`reply_to`), `MAIL FROM` (`env_from`) and of every `DKIM_ALLOW` option (`dkim_pass`) | `value`, `domain`, `sld`, `location` |
/// | `email` | the From, Reply-To and `MAIL FROM` addresses | `email`, `location` |
/// | `url` | the distinct links | `url`, `scheme`, `host`, `path`, `path_query`, `sld` |
///
/// Identical query names are asked once, and at most [`MAX_QUERIES`] are asked per message.
/// Lists that fail to answer are left out; the check never fails because of DNS. Symbols carry
/// the item (domain or address) as their option for `ip` and `domain`. Skipped for
/// authenticated clients.
pub struct DnsListCheck {
    rules: Arc<RuleSet>,
    resolver: Arc<dyn Resolver>,
    declared: Vec<SymbolName>,
}

impl DnsListCheck {
    /// Builds the check over the rule set's DNS lists.
    pub fn new(rules: Arc<RuleSet>, resolver: Arc<dyn Resolver>) -> Self {
        let declared = rules.dnsbl_symbols().into_iter().collect();
        DnsListCheck {
            rules,
            resolver,
            declared,
        }
    }
}

struct Item {
    scope: Scope,
    vars: HashMap<&'static str, Value>,
    option: Option<String>,
}

fn ip_item(ip: IpAddr, location: &'static str) -> Item {
    let reverse = list_query(ip, "x");
    let reverse = reverse.strip_suffix(".x").unwrap_or(&reverse).to_string();
    Item {
        scope: Scope::Ip,
        vars: HashMap::from([
            ("ip", Value::from(ip.to_string())),
            ("ip_reverse", Value::Str(reverse)),
            ("is_v4", Value::Bool(ip.is_ipv4())),
            ("is_v6", Value::Bool(ip.is_ipv6())),
            ("location", Value::from(location)),
        ]),
        option: Some(ip.to_string()),
    }
}

fn domain_item(domain: &str, location: &'static str) -> Option<Item> {
    let domain = normalize(domain).ok()?;
    if domain.parse::<IpAddr>().is_ok() || !domain.contains('.') {
        return None;
    }
    let sld = psl::domain_str(&domain).unwrap_or(&domain).to_string();
    Some(Item {
        scope: Scope::Domain,
        vars: HashMap::from([
            ("value", Value::from(sld.as_str())),
            ("domain", Value::from(domain.as_str())),
            ("sld", Value::from(sld.as_str())),
            ("location", Value::from(location)),
        ]),
        option: Some(sld),
    })
}

/// Addresses written as `[192.0.2.1]` or `[IPv6:2001:db8::1]` in the `Received` fields.
fn received_ips(message: &Message) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for header in message.headers_named("received") {
        let text = header.value_str();
        let mut rest = text.as_ref();
        while let Some(open) = rest.find('[') {
            let Some(close) = rest[open..].find(']') else {
                break;
            };
            let inside = &rest[open + 1..open + close];
            let inside = inside.strip_prefix("IPv6:").unwrap_or(inside);
            if let Ok(ip) = inside.parse::<IpAddr>()
                && !out.contains(&ip)
            {
                out.push(ip);
            }
            rest = &rest[open + close + 1..];
        }
    }
    out
}

fn items(ctx: &Context<'_>, message: &Message) -> Vec<Item> {
    let mut items = Vec::new();
    let client = ctx.envelope.client_ip.filter(|ip| is_listable(*ip));
    if let Some(ip) = client {
        items.push(ip_item(ip, "tcp"));
    }
    for ip in received_ips(message) {
        if is_listable(ip) && Some(ip) != client {
            items.push(ip_item(ip, "received"));
        }
    }

    let parsed = parse(message, ctx.envelope);
    let mut domains: HashSet<(String, &'static str)> = HashSet::new();
    let mut add_domain = |domain: &str, location: &'static str| {
        if domains.insert((domain.to_string(), location))
            && let Some(item) = domain_item(domain, location)
        {
            items.push(item);
        }
    };
    for url in &parsed.urls {
        add_domain(&url.host, "url");
    }
    for (location, address) in &parsed.addresses {
        if matches!(*location, "from" | "reply_to" | "env_from")
            && let Some(domain) = address.field("domain").as_str()
        {
            add_domain(domain, location);
        }
    }
    for symbol in ctx
        .earlier
        .iter()
        .filter(|s| s.name.as_str() == "DKIM_ALLOW")
    {
        for domain in &symbol.options {
            add_domain(domain, "dkim_pass");
        }
    }

    let mut emails = HashSet::new();
    for (location, address) in &parsed.addresses {
        if matches!(*location, "from" | "reply_to" | "env_from")
            && let Some(email) = address.field("email").as_str()
            && email.contains('@')
            && emails.insert(email.to_string())
        {
            items.push(Item {
                scope: Scope::Email,
                vars: HashMap::from([
                    ("email", Value::from(email)),
                    ("location", Value::from(*location)),
                ]),
                option: None,
            });
        }
    }

    for url in &parsed.urls {
        items.push(Item {
            scope: Scope::Url,
            vars: HashMap::from([
                ("url", Value::from(url.raw.as_str())),
                ("scheme", Value::from(url.scheme.as_str())),
                ("host", Value::from(url.host.as_str())),
                ("path", Value::from(url.path.as_str())),
                ("path_query", Value::from(url.path_query())),
                ("sld", Value::from(url.registrable())),
            ]),
            option: None,
        });
    }
    items
}

#[async_trait]
impl Check for DnsListCheck {
    fn name(&self) -> &str {
        "rules.dnsbl"
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
        if ctx.envelope.authenticated {
            return Ok(Vec::new());
        }
        let message = ctx
            .message
            .ok_or_else(|| CheckError::Failed("no message at the data stage".into()))?;
        let items = items(ctx, message);
        let mut env = RuleEnv {
            message: HashMap::new(),
            scoped: HashMap::new(),
            symbols: ctx.earlier.iter().map(|s| s.name.to_string()).collect(),
            lists: self.rules.lists(),
        };

        let mut queries: Vec<String> = Vec::new();
        let mut asks: Vec<(usize, usize, usize)> = Vec::new();
        for (list_index, list) in self.rules.dnsbl().iter().enumerate() {
            for (item_index, item) in items
                .iter()
                .enumerate()
                .filter(|(_, i)| i.scope == list.scope)
            {
                env.scoped = item.vars.clone();
                let Value::Str(name) = list.zone.eval(&env) else {
                    continue;
                };
                let Ok(name) = normalize(&name) else { continue };
                let query = match queries.iter().position(|q| *q == name) {
                    Some(q) => q,
                    None if queries.len() < MAX_QUERIES => {
                        queries.push(name);
                        queries.len() - 1
                    }
                    None => continue,
                };
                asks.push((list_index, item_index, query));
            }
        }
        let answers = join_all(queries.iter().map(|q| self.resolver.ipv4(q))).await;

        let mut out: Vec<Symbol> = Vec::new();
        for (list_index, item_index, query) in asks {
            let codes = match &answers[query] {
                Ok(codes) => codes,
                Err(_) => continue,
            };
            let list = &self.rules.dnsbl()[list_index];
            let item = &items[item_index];
            for code in codes {
                env.scoped = item.vars.clone();
                env.scoped.insert(
                    "octets",
                    Value::List(
                        code.octets()
                            .iter()
                            .map(|o| Value::Int(i64::from(*o)))
                            .collect(),
                    ),
                );
                let Value::Str(name) = list.tag.eval(&env) else {
                    continue;
                };
                let Some(declared) = self.declared.iter().find(|d| d.as_str() == name) else {
                    continue;
                };
                let symbol = match out.iter_mut().find(|s| &s.name == declared) {
                    Some(existing) => existing,
                    None => {
                        out.push(Symbol::new(declared.clone()));
                        out.last_mut().expect("just pushed")
                    }
                };
                if let Some(option) = &item.option
                    && !symbol.options.contains(option)
                {
                    symbol.push_option(option.clone());
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
