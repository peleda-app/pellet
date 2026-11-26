use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, RwLock},
    time::Duration,
};

use pellet_core::{Action, ScoreTable, SymbolName};

use crate::condition::Condition;

/// What a rule is evaluated against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Scope {
    /// Once per message.
    Any,
    /// Once per top-level header field.
    Header,
    /// Once per address in the envelope and the address headers.
    Email,
    /// Once per URL in the message.
    Url,
    /// Once per domain (DNS lists).
    Domain,
    /// Once per IP address (DNS lists).
    Ip,
}

impl Scope {
    fn parse(name: &str) -> Option<Scope> {
        Some(match name {
            "any" => Scope::Any,
            "header" => Scope::Header,
            "email" => Scope::Email,
            "url" => Scope::Url,
            "domain" => Scope::Domain,
            "ip" => Scope::Ip,
            _ => return None,
        })
    }

    /// Variables a rule of this scope may read, besides the message-wide ones.
    pub fn variables(self) -> &'static [&'static str] {
        match self {
            Scope::Any => &[],
            Scope::Header => &[
                "name",
                "name_lower",
                "value",
                "value_lower",
                "raw",
                "raw_lower",
            ],
            Scope::Email => &["email", "name", "local", "domain", "sld", "location"],
            Scope::Url => &["url", "scheme", "host", "path", "path_query", "sld"],
            Scope::Domain => &["domain", "sld", "value", "ip", "location", "octets"],
            Scope::Ip => &["ip", "ip_reverse", "is_v4", "is_v6", "location", "octets"],
        }
    }
}

/// Variables every scope may read.
pub const MESSAGE_VARIABLES: [&str; 5] = ["subject", "from", "reply_to", "env_from", "body"];

/// One `[rule.*]` table.
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    /// The table key, such as `STWT_FAKE_REPLY`.
    pub id: String,
    /// What it runs against.
    pub scope: Scope,
    /// Lower runs first; rules see the symbols of rules that ran before them.
    pub priority: i64,
    /// Its result is the name of the symbol to emit, or false.
    pub condition: Condition,
}

/// One `[dnsbl.*]` table: a zone to query and the meaning of its answers.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsblRule {
    /// The table key.
    pub id: String,
    /// What is looked up.
    pub scope: Scope,
    /// Gives the name to query, or false to skip.
    pub zone: Condition,
    /// Gives the symbol for an answer (`octets`), or false.
    pub tag: Condition,
}

/// One `[http-list.*]` table: a list fetched over HTTP, off unless a deployment enables it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpList {
    /// The table key, such as `STWT_OPENPHISH`.
    pub id: String,
    /// The name rules use with `key_exists`: the key in lowercase.
    pub name: String,
    /// Where to fetch it.
    pub url: String,
    /// How its lines hold keys.
    pub format: ListFormat,
    /// Whether the download is gzip-compressed.
    pub gzipped: bool,
    /// How long a successful download stays fresh.
    pub refresh: Duration,
    /// How long to wait after a failed download.
    pub retry: Duration,
    /// Longest a download may take.
    pub timeout: Duration,
    /// Largest download, in bytes, after decompression.
    pub max_size: usize,
    /// Most keys kept.
    pub max_entries: usize,
    /// Longest key kept, in bytes; longer lines are skipped.
    pub max_entry_size: usize,
}

/// How the lines of a remote list hold their keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListFormat {
    /// One key per line.
    Lines,
    /// Delimited fields; the key is field `key` (from zero), the first line may be a header.
    Csv {
        /// The field separator.
        separator: char,
        /// Which field holds the key.
        key: usize,
        /// Whether the first line is a header.
        skip_first: bool,
    },
}

/// The 64-bit fingerprint of a list key: FNV-1a over the key lowercased and trimmed.
pub fn fingerprint(key: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for b in key.trim().to_lowercase().bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// A large list kept as sorted fingerprints: 8 bytes per key, looked up by binary search.
/// Two keys sharing a fingerprint is possible but about one in 2^64 per pair.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fingerprints(Vec<u64>);

impl Fingerprints {
    /// From keys, normalized by [`fingerprint`].
    pub fn from_keys<S: AsRef<str>>(keys: impl IntoIterator<Item = S>) -> Self {
        Self::from_raw(keys.into_iter().map(|k| fingerprint(k.as_ref())).collect())
    }

    /// From fingerprints already computed, in any order.
    pub fn from_raw(mut raw: Vec<u64>) -> Self {
        raw.sort_unstable();
        raw.dedup();
        Fingerprints(raw)
    }

    /// Whether a key is in the list.
    pub fn contains(&self, key: &str) -> bool {
        self.0.binary_search(&fingerprint(key)).is_ok()
    }

    /// The fingerprints, sorted.
    pub fn as_slice(&self) -> &[u64] {
        &self.0
    }

    /// Number of keys.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A handle to the remote lists of a [`Lists`], shared by every clone, so a fetcher can replace
/// a list while checks read it.
#[derive(Debug, Clone, Default)]
pub struct RemoteLists(Arc<RwLock<HashMap<String, Arc<Fingerprints>>>>);

impl RemoteLists {
    /// Replaces a list.
    pub fn set(&self, name: &str, list: Fingerprints) {
        self.0
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .insert(name.to_string(), Arc::new(list));
    }

    /// Number of keys in a list; 0 when it was never set.
    pub fn len(&self, name: &str) -> usize {
        self.get(name).map_or(0, |l| l.len())
    }

    fn get(&self, name: &str) -> Option<Arc<Fingerprints>> {
        self.0
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(name)
            .cloned()
    }
}

impl PartialEq for RemoteLists {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for RemoteLists {}

/// Named sets of keys for `key_exists`: lists from data files, plus remote lists replaced at
/// run time through [`Lists::remote`]. A list that does not exist is empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lists(HashMap<String, HashMap<String, String>>, RemoteLists);

impl Lists {
    /// Whether `list` holds `key` (keys are stored lowercase).
    pub fn contains(&self, list: &str, key: &str) -> bool {
        self.0.get(list).is_some_and(|l| l.contains_key(key))
            || self.1.get(list).is_some_and(|l| l.contains(key))
    }

    /// The handle to replace remote lists, shared by every clone of these lists.
    pub fn remote(&self) -> RemoteLists {
        self.1.clone()
    }

    /// The value next to a key in `key = value` lists.
    pub fn value(&self, list: &str, key: &str) -> Option<&str> {
        self.0.get(list)?.get(key).map(String::as_str)
    }

    /// Adds or replaces a list from text: one key per line, `key = value` keeps both, blank lines
    /// and `#` comments are skipped, keys are lowercased.
    pub fn insert_text(&mut self, name: &str, text: &str) {
        let entries = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|line| match line.split_once('=') {
                Some((key, value)) => (key.trim().to_lowercase(), value.trim().to_string()),
                None => (line.to_lowercase(), String::new()),
            })
            .collect();
        self.0.insert(name.to_string(), entries);
    }

    /// Every key and value of a list, in no particular order; empty for a missing list.
    pub fn entries(&self, list: &str) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .get(list)
            .into_iter()
            .flat_map(|l| l.iter().map(|(k, v)| (k.as_str(), v.as_str())))
    }

    /// The names of every list.
    pub fn names(&self) -> BTreeSet<&str> {
        self.0.keys().map(String::as_str).collect()
    }

    /// Number of keys in a list.
    pub fn len(&self, list: &str) -> usize {
        self.0.get(list).map_or(0, HashMap::len)
    }
}

/// Data that failed to load.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{file}: {item}: {message}")]
pub struct DataError {
    /// The file.
    pub file: String,
    /// The table key or line.
    pub item: String,
    /// What is wrong.
    pub message: String,
}

/// Every rule, list and score, checked and ready to evaluate.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
    dnsbl: Vec<DnsblRule>,
    http_lists: Vec<HttpList>,
    scores: ScoreTable,
    lists: Lists,
}

const BUNDLED_RULES: [(&str, &str); 7] = [
    (
        "composites.toml",
        include_str!("../../../data/stalwart/rules/composites.toml"),
    ),
    (
        "dnsbl.toml",
        include_str!("../../../data/stalwart/rules/dnsbl.toml"),
    ),
    (
        "from.toml",
        include_str!("../../../data/stalwart/rules/from.toml"),
    ),
    (
        "header.toml",
        include_str!("../../../data/stalwart/rules/header.toml"),
    ),
    (
        "recipient.toml",
        include_str!("../../../data/stalwart/rules/recipient.toml"),
    ),
    (
        "subject.toml",
        include_str!("../../../data/stalwart/rules/subject.toml"),
    ),
    (
        "url.toml",
        include_str!("../../../data/stalwart/rules/url.toml"),
    ),
];

const BUNDLED_LISTS: [(&str, &str); 4] = [
    (
        "file-extensions",
        include_str!("../../../data/stalwart/lists/file_extensions.txt"),
    ),
    (
        "surbl-hashbl",
        include_str!("../../../data/stalwart/lists/surbl-hashbl.txt"),
    ),
    (
        "trusted-domains",
        include_str!("../../../data/stalwart/lists/trusted_domains.txt"),
    ),
    (
        "url-redirectors",
        include_str!("../../../data/stalwart/lists/url_redirectors.txt"),
    ),
];

const BUNDLED_SCORES: &str = include_str!("../../../data/stalwart/lists/scores.txt");
const PELLET_SCORES: &str = include_str!("../../../data/pellet/scores.txt");
const PELLET_CLICK_TRACKERS: &str = include_str!("../../../data/pellet/click_trackers.txt");
const PELLET_ALIAS_RELAYS: &str = include_str!("../../../data/pellet/alias_relays.txt");
const BUNDLED_HTTP_LISTS: &str = include_str!("../../../data/stalwart/lists/http_lists.toml");

impl RuleSet {
    /// The data compiled into this crate from `data/`.
    pub fn bundled() -> Result<RuleSet, DataError> {
        let mut set = RuleSet::default();
        for (file, text) in BUNDLED_RULES {
            set.add_rules(file, text)?;
        }
        for (name, text) in BUNDLED_LISTS {
            set.lists.insert_text(name, text);
        }
        set.lists
            .insert_text("click-trackers", PELLET_CLICK_TRACKERS);
        set.lists.insert_text("alias-relays", PELLET_ALIAS_RELAYS);
        set.add_scores("scores.txt", BUNDLED_SCORES)?;
        set.add_scores("pellet/scores.txt", PELLET_SCORES)?;
        set.add_rules("http_lists.toml", BUNDLED_HTTP_LISTS)?;
        Ok(set)
    }

    /// Adds `[rule.*]`, `[dnsbl.*]` and `[http-list.*]` tables from a TOML file. Every expression
    /// is parsed and checked against its scope; disabled tables (`enable = false`) are checked
    /// and then left out.
    pub fn add_rules(&mut self, file: &str, text: &str) -> Result<(), DataError> {
        let err = |item: &str, message: String| DataError {
            file: file.to_string(),
            item: item.to_string(),
            message,
        };
        let root: toml::Table = toml::from_str(text).map_err(|e| err("-", e.to_string()))?;
        for (kind, tables) in root {
            let toml::Value::Table(tables) = tables else {
                return Err(err(&kind, "expected a table of tables".into()));
            };
            for (id, table) in tables {
                let toml::Value::Table(table) = table else {
                    return Err(err(&id, "expected a table".into()));
                };
                let enabled = table
                    .get("enable")
                    .and_then(toml::Value::as_bool)
                    .unwrap_or(true);
                match kind.as_str() {
                    "rule" => {
                        let rule = self.read_rule(&id, &table).map_err(|m| err(&id, m))?;
                        if enabled {
                            self.rules.push(rule);
                        }
                    }
                    "dnsbl" => {
                        let rule = read_dnsbl(&id, &table).map_err(|m| err(&id, m))?;
                        if enabled {
                            self.dnsbl.push(rule);
                        }
                    }
                    "http-list" => {
                        let list = read_http_list(&id, &table).map_err(|m| err(&id, m))?;
                        if enabled {
                            self.http_lists.push(list);
                        }
                    }
                    other => return Err(err(&id, format!("unknown table kind `{other}`"))),
                }
            }
        }
        self.rules
            .sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
        Ok(())
    }

    fn read_rule(&self, id: &str, table: &toml::Table) -> Result<Rule, String> {
        for key in table.keys() {
            if !matches!(key.as_str(), "scope" | "priority" | "condition" | "enable") {
                return Err(format!("unknown key `{key}`"));
            }
        }
        let scope = scope_of(table)?;
        let priority = table
            .get("priority")
            .and_then(toml::Value::as_integer)
            .unwrap_or(0);
        let condition = condition_of(table, "condition")?;
        check_variables(&condition, scope, &[])?;
        Ok(Rule {
            id: id.to_string(),
            scope,
            priority,
            condition,
        })
    }

    /// Adds scores from `SYMBOL = score` lines; later lines win. A score of `tag`, `greylist` or
    /// `reject` forces that action instead.
    pub fn add_scores(&mut self, file: &str, text: &str) -> Result<(), DataError> {
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let err = |message: String| DataError {
                file: file.to_string(),
                item: format!("line {}", n + 1),
                message,
            };
            let (name, score) = line
                .split_once('=')
                .ok_or_else(|| err("expected `SYMBOL = score`".into()))?;
            let name = SymbolName::new(name.trim()).map_err(|e| err(e.to_string()))?;
            let score = score.trim();
            match Action::parse(score) {
                Some(action @ (Action::Tag | Action::Greylist | Action::Reject)) => {
                    self.scores.force(name, action)
                }
                _ => {
                    let score: f64 = score
                        .parse()
                        .map_err(|_| err(format!("invalid score {score:?}")))?;
                    self.scores
                        .insert(name, score)
                        .map_err(|e| err(e.to_string()))?;
                }
            }
        }
        Ok(())
    }

    /// Mutable access to the lists, to add a deployment's own.
    pub fn lists_mut(&mut self) -> &mut Lists {
        &mut self.lists
    }

    /// Rules in evaluation order: by priority, then by id.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// DNS list definitions.
    pub fn dnsbl(&self) -> &[DnsblRule] {
        &self.dnsbl
    }

    /// Remote list definitions.
    pub fn http_lists(&self) -> &[HttpList] {
        &self.http_lists
    }

    /// Every score.
    pub fn scores(&self) -> &ScoreTable {
        &self.scores
    }

    /// Every list.
    pub fn lists(&self) -> &Lists {
        &self.lists
    }

    /// Symbols the DNS list definitions can give: every symbol-shaped literal in a `tag`.
    pub fn dnsbl_symbols(&self) -> BTreeSet<SymbolName> {
        self.dnsbl
            .iter()
            .flat_map(|d| d.tag.results().flat_map(|e| e.string_literals()))
            .filter_map(|l| SymbolName::new(&l).ok())
            .collect()
    }

    /// Every symbol the rules read with `$NAME`.
    pub fn referenced_symbols(&self) -> BTreeSet<String> {
        self.rules
            .iter()
            .flat_map(|r| r.condition.exprs().flat_map(|e| e.symbols()))
            .collect()
    }

    /// Symbols the rules of `scopes` can emit: every literal symbol name a `then` or `else` can
    /// give, plus, for computed names, every scored symbol that starts with a literal prefix.
    pub fn symbols(&self, scopes: &[Scope]) -> BTreeSet<SymbolName> {
        let mut literals = BTreeSet::new();
        let mut prefixes = BTreeSet::new();
        for rule in self.rules.iter().filter(|r| scopes.contains(&r.scope)) {
            for result in rule.condition.results() {
                for literal in result.string_literals() {
                    if let Ok(name) = SymbolName::new(&literal) {
                        if literal.ends_with('_') {
                            prefixes.insert(literal);
                        } else {
                            literals.insert(name);
                        }
                    }
                }
            }
        }
        literals.extend(
            self.scores
                .names()
                .filter(|s| prefixes.iter().any(|p| s.as_str().starts_with(p.as_str())))
                .cloned(),
        );
        literals
    }
}

fn read_http_list(id: &str, table: &toml::Table) -> Result<HttpList, String> {
    let get = |dotted: &str| -> Option<&toml::Value> {
        let mut parts = dotted.split('.');
        let mut value = table.get(parts.next()?)?;
        for part in parts {
            value = value.get(part)?;
        }
        Some(value)
    };
    let millis = |key: &str, default: u64| -> Result<Duration, String> {
        match get(key) {
            None => Ok(Duration::from_millis(default)),
            Some(v) => v
                .as_integer()
                .filter(|n| *n > 0)
                .map(|n| Duration::from_millis(n as u64))
                .ok_or_else(|| format!("`{key}` must be a positive number of milliseconds")),
        }
    };
    let count = |key: &str, default: usize| -> Result<usize, String> {
        match get(key) {
            None => Ok(default),
            Some(v) => v
                .as_integer()
                .filter(|n| *n > 0)
                .map(|n| n as usize)
                .ok_or_else(|| format!("`{key}` must be a positive number")),
        }
    };
    let url = get("url")
        .and_then(toml::Value::as_str)
        .ok_or("missing `url`")?
        .to_string();
    let format = match get("format")
        .and_then(toml::Value::as_str)
        .unwrap_or("list")
    {
        "list" => ListFormat::Lines,
        "csv" => ListFormat::Csv {
            separator: get("separator")
                .and_then(toml::Value::as_str)
                .and_then(|s| s.chars().next())
                .unwrap_or(','),
            key: match get("index.key") {
                None => 0,
                Some(v) => v
                    .as_integer()
                    .filter(|n| *n >= 0)
                    .map(|n| n as usize)
                    .ok_or("`index.key` must be a field number from 0")?,
            },
            skip_first: get("skip-first")
                .and_then(toml::Value::as_bool)
                .unwrap_or(false),
        },
        other => return Err(format!("unknown list format `{other}`")),
    };
    Ok(HttpList {
        name: id.to_lowercase(),
        id: id.to_string(),
        url,
        format,
        gzipped: get("gzipped")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false),
        refresh: millis("refresh", 86_400_000)?,
        retry: millis("retry", 3_600_000)?,
        timeout: millis("timeout", 30_000)?,
        max_size: count("limits.size", 10 * 1024 * 1024)?,
        max_entries: count("limits.entries", 100_000)?,
        max_entry_size: count("limits.entry-size", 512)?,
    })
}

fn scope_of(table: &toml::Table) -> Result<Scope, String> {
    let name = table
        .get("scope")
        .and_then(toml::Value::as_str)
        .ok_or("missing `scope`")?;
    Scope::parse(name).ok_or_else(|| format!("unknown scope `{name}`"))
}

fn condition_of(table: &toml::Table, key: &str) -> Result<Condition, String> {
    let value = table.get(key).ok_or_else(|| format!("missing `{key}`"))?;
    Condition::from_toml(value).map_err(|e| format!("{key}: {e}"))
}

fn check_variables(condition: &Condition, scope: Scope, extra: &[&str]) -> Result<(), String> {
    for expr in condition.exprs() {
        for var in expr.variables() {
            let var = var.as_str();
            if !MESSAGE_VARIABLES.contains(&var)
                && !scope.variables().contains(&var)
                && !extra.contains(&var)
            {
                return Err(format!(
                    "variable `{var}` is not available in scope {scope:?}"
                ));
            }
        }
    }
    Ok(())
}

fn read_dnsbl(id: &str, table: &toml::Table) -> Result<DnsblRule, String> {
    for key in table.keys() {
        if !matches!(key.as_str(), "scope" | "zone" | "tag" | "enable") {
            return Err(format!("unknown key `{key}`"));
        }
    }
    let scope = scope_of(table)?;
    let zone = condition_of(table, "zone")?;
    let tag = condition_of(table, "tag")?;
    check_variables(&zone, scope, &["location"])?;
    check_variables(&tag, scope, &["location", "octets"])?;
    Ok(DnsblRule {
        id: id.to_string(),
        scope,
        zone,
        tag,
    })
}

#[cfg(test)]
mod tests;
