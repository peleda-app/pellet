use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Context;
use pellet_check_classifier::ClassifierConfig;
use pellet_check_ip::{DnsblResult, DnsblZone};
use pellet_check_pyzor::PyzorConfig;
use pellet_check_reputation::ReplyConfig;
use pellet_classifier::Params;
use pellet_core::{ScoreTable, SymbolName, Thresholds};
use pellet_engine::DEFAULT_DEADLINE;
use pellet_rules::{HttpList, RuleSet};
use pellet_server::DEFAULT_MAX_MESSAGE_SIZE;
use serde::Deserialize;

/// The configuration file.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Action thresholds; missing ones are off, a missing table keeps the defaults.
    pub thresholds: Thresholds,
    /// Score per symbol name.
    pub scores: BTreeMap<String, f64>,
    /// Time the checks of one stage may take, in milliseconds.
    pub deadline_ms: Option<u64>,
    /// How to reach DNS.
    pub dns: Dns,
    /// DNS lists asked about the client address.
    pub dnsbl: Vec<Dnsbl>,
    /// Rule data.
    pub rules: Rules,
    /// The classifier.
    pub classifier: Classifier,
    /// The HTTP API.
    pub server: Server,
    /// Kept state: reputation, caches.
    pub state: StateFile,
    /// Remote lists from the rules data.
    pub feeds: Feeds,
    /// Spam trap addresses.
    pub traps: Traps,
    /// Recognizing replies to sent mail.
    pub replies: Replies,
    /// Pyzor lookups.
    pub pyzor: Pyzor,
}

/// The `[traps]` table.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Traps {
    /// Trap addresses, and `@domain` entries for whole domains; empty turns the check off.
    pub addresses: Vec<String>,
}

/// The `[replies]` table.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Replies {
    /// Whether replies to mail recorded through `/v1/sent` are recognized.
    pub enabled: bool,
    /// Days a sent message is remembered.
    pub ttl_days: u64,
}

impl Default for Replies {
    fn default() -> Self {
        Replies {
            enabled: true,
            ttl_days: 90,
        }
    }
}

/// The `[pyzor]` table.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Pyzor {
    /// Whether digests are sent to Pyzor servers; off until a deployment accepts that.
    pub enabled: bool,
    /// Servers as `host:port`, asked in order.
    pub servers: Vec<String>,
    /// Reports a digest needs before `PYZOR` fires.
    pub min_count: u64,
    /// Longest wait for one server, in milliseconds.
    pub timeout_ms: u64,
}

impl Default for Pyzor {
    fn default() -> Self {
        let defaults = PyzorConfig::default();
        Pyzor {
            enabled: false,
            servers: defaults.servers,
            min_count: defaults.min_count,
            timeout_ms: u64::try_from(defaults.timeout.as_millis()).unwrap_or(u64::MAX),
        }
    }
}

/// The `[feeds]` table.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Feeds {
    /// Names of the `[http-list.*]` lists to fetch, such as `stwt_openphish`; each has its own
    /// terms of use.
    pub enabled: Vec<String>,
    /// Where the lists are cached between restarts.
    pub dir: Option<PathBuf>,
    /// Most keys any one list may hold, whatever its definition allows.
    pub max_entries: usize,
}

impl Default for Feeds {
    fn default() -> Self {
        Feeds {
            enabled: Vec::new(),
            dir: None,
            max_entries: 200_000,
        }
    }
}

/// The `[state]` table.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StateFile {
    /// The snapshot file; none keeps state in memory only.
    pub path: Option<PathBuf>,
    /// Most keys held in memory.
    pub entries: usize,
    /// Seconds between snapshots in `serve`.
    pub save_interval_secs: u64,
}

impl Default for StateFile {
    fn default() -> Self {
        StateFile {
            path: None,
            entries: 100_000,
            save_interval_secs: 60,
        }
    }
}

/// The `[server]` table.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    /// Address and port to listen on.
    pub listen: SocketAddr,
    /// Bearer token every API request must carry; none means no check.
    pub token: Option<String>,
    /// Largest message accepted, in bytes.
    pub max_message_size: usize,
}

impl Default for Server {
    fn default() -> Self {
        Server {
            listen: SocketAddr::from(([127, 0, 0, 1], 11334)),
            token: None,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        }
    }
}

/// The `[classifier]` table.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Classifier {
    /// Table size of a new model, as a power of two.
    pub bits: u8,
    /// Ham samples needed before the classifier speaks.
    pub min_ham: u64,
    /// Spam samples needed before the classifier speaks.
    pub min_spam: u64,
    /// Whether strong signals train the model by themselves.
    pub auto_learn: bool,
    /// The model file `serve` loads, saves on an interval and at shutdown.
    pub model: Option<PathBuf>,
    /// Seconds between saves of a changed model.
    pub save_interval_secs: u64,
}

impl Default for Classifier {
    fn default() -> Self {
        let defaults = ClassifierConfig::default();
        Classifier {
            bits: Params::default().bits,
            min_ham: defaults.min_ham,
            min_spam: defaults.min_spam,
            auto_learn: defaults.auto_learn,
            model: None,
            save_interval_secs: 60,
        }
    }
}

/// The `[rules]` table.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rules {
    /// Whether the rules, lists and scores compiled into Pellet are used.
    pub bundled: bool,
    /// Whether the public DNS lists defined in the rules are queried; each list has its own
    /// terms of use, so this is off until a deployment accepts them.
    pub dns_lists: bool,
}

impl Default for Rules {
    fn default() -> Self {
        Rules {
            bundled: true,
            dns_lists: false,
        }
    }
}

/// The `[dns]` table.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dns {
    /// Recursive resolvers; empty means the system configuration.
    pub nameservers: Vec<IpAddr>,
    /// Longest wait for one lookup, in milliseconds.
    pub timeout_ms: u64,
    /// Most answers cached.
    pub cache_size: u64,
    /// This server's host name, used by SPF macros.
    pub hostname: String,
}

impl Default for Dns {
    fn default() -> Self {
        Dns {
            nameservers: Vec::new(),
            timeout_ms: 2000,
            cache_size: 4096,
            hostname: "localhost".into(),
        }
    }
}

/// One `[[dnsbl]]` entry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dnsbl {
    /// The zone to query.
    pub zone: String,
    /// Whether the zone lists IPv6 addresses.
    #[serde(default)]
    pub ipv6: bool,
    /// Answer codes and their symbols.
    pub results: Vec<DnsblCode>,
}

/// One answer mapping of a `[[dnsbl]]` entry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsblCode {
    /// Last octets of `127.0.0.x` answers that mean this symbol.
    pub codes: Vec<u8>,
    /// The symbol.
    pub symbol: String,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn parse(text: &str) -> anyhow::Result<Self> {
        Ok(toml::from_str(text)?)
    }

    /// The enabled remote lists and their cache directory; an unknown name or a missing
    /// directory is an error.
    pub fn feeds(&self, rules: &RuleSet) -> anyhow::Result<Vec<HttpList>> {
        if self.feeds.enabled.is_empty() {
            return Ok(Vec::new());
        }
        if self.feeds.dir.is_none() {
            anyhow::bail!("[feeds] enabled needs [feeds] dir");
        }
        self.feeds
            .enabled
            .iter()
            .map(|name| {
                rules
                    .http_lists()
                    .iter()
                    .find(|l| l.name == name.to_lowercase())
                    .cloned()
                    .with_context(|| format!("no remote list named {name:?}"))
            })
            .collect()
    }

    pub fn rule_set(&self) -> anyhow::Result<RuleSet> {
        Ok(if self.rules.bundled {
            RuleSet::bundled()?
        } else {
            RuleSet::default()
        })
    }

    pub fn scores(&self, base: &ScoreTable) -> anyhow::Result<ScoreTable> {
        let mut table = base.clone();
        for (name, score) in &self.scores {
            table.insert(SymbolName::new(name)?, *score)?;
        }
        Ok(table)
    }

    pub fn classifier_config(&self) -> ClassifierConfig {
        ClassifierConfig {
            min_ham: self.classifier.min_ham,
            min_spam: self.classifier.min_spam,
            auto_learn: self.classifier.auto_learn,
            ..ClassifierConfig::default()
        }
    }

    /// Pyzor's settings, or `None` when it is off.
    pub fn pyzor_config(&self) -> Option<PyzorConfig> {
        self.pyzor.enabled.then(|| PyzorConfig {
            servers: self.pyzor.servers.clone(),
            min_count: self.pyzor.min_count,
            timeout: Duration::from_millis(self.pyzor.timeout_ms),
        })
    }

    pub fn reply_config(&self) -> ReplyConfig {
        ReplyConfig {
            ttl: Duration::from_secs(self.replies.ttl_days.max(1) * 24 * 3600),
            ..ReplyConfig::default()
        }
    }

    pub fn deadline(&self) -> Duration {
        self.deadline_ms
            .map_or(DEFAULT_DEADLINE, Duration::from_millis)
    }

    pub fn dnsbl_zones(&self) -> anyhow::Result<Vec<DnsblZone>> {
        self.dnsbl
            .iter()
            .map(|list| {
                let mut results = Vec::new();
                for code in &list.results {
                    let symbol = SymbolName::new(&code.symbol)
                        .with_context(|| format!("dnsbl {}", list.zone))?;
                    for &octet in &code.codes {
                        results.push(DnsblResult {
                            codes: octet..=octet,
                            symbol: symbol.clone(),
                        });
                    }
                }
                Ok(DnsblZone {
                    zone: list.zone.clone(),
                    ipv6: list.ipv6,
                    results,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use pellet_core::SymbolName;

    use super::*;

    #[test]
    fn parses_scores_thresholds_and_deadline() {
        let config = Config::parse(
            "deadline_ms = 250\n[thresholds]\ntag = 5.0\nreject = 12.5\n[scores]\nMISSING_MID = 2.5\n",
        )
        .unwrap();
        assert_eq!(config.thresholds.tag, Some(5.0));
        assert_eq!(config.thresholds.greylist, None);
        assert_eq!(config.thresholds.reject, Some(12.5));
        assert_eq!(config.deadline(), Duration::from_millis(250));
        let scores = config.scores(&ScoreTable::new()).unwrap();
        assert_eq!(scores.score(&SymbolName::new("MISSING_MID").unwrap()), 2.5);
    }

    #[test]
    fn config_scores_override_bundled_ones() {
        let config = Config::parse("[scores]\nMISSING_MID = 9.0\n").unwrap();
        let bundled = config.rule_set().unwrap();
        let scores = config.scores(bundled.scores()).unwrap();
        assert_eq!(scores.score(&SymbolName::new("MISSING_MID").unwrap()), 9.0);
        assert_eq!(scores.score(&SymbolName::new("MISSING_DATE").unwrap()), 1.0);

        let off = Config::parse("[rules]\nbundled = false\n").unwrap();
        assert!(off.rule_set().unwrap().rules().is_empty());
    }

    #[test]
    fn feeds_name_known_lists_and_need_a_directory() {
        let rules = RuleSet::bundled().unwrap();
        let ok = Config::parse("[feeds]\nenabled = [\"STWT_OpenPhish\"]\ndir = \"/tmp/feeds\"\n")
            .unwrap();
        assert_eq!(ok.feeds(&rules).unwrap()[0].name, "stwt_openphish");
        assert!(
            Config::parse("[feeds]\nenabled = [\"stwt_openphish\"]\n")
                .unwrap()
                .feeds(&rules)
                .is_err()
        );
        assert!(
            Config::parse("[feeds]\nenabled = [\"nope\"]\ndir = \"/tmp\"\n")
                .unwrap()
                .feeds(&rules)
                .is_err()
        );
        assert!(Config::default().feeds(&rules).unwrap().is_empty());
    }

    #[test]
    fn empty_file_keeps_defaults() {
        let config = Config::parse("").unwrap();
        assert_eq!(config.thresholds, Thresholds::default());
        assert_eq!(config.deadline(), DEFAULT_DEADLINE);
        assert!(config.scores(&ScoreTable::new()).unwrap().is_empty());
        assert!(config.rules.bundled);
        assert!(!config.rules.dns_lists);
        assert_eq!(config.classifier.bits, 18);
        assert_eq!(config.server.listen.port(), 11334);
        assert_eq!(config.state.entries, 100_000);
        assert!(config.state.path.is_none());
        assert!(config.server.listen.ip().is_loopback());
        assert_eq!(config.classifier_config().min_spam, 50);
        assert!(config.traps.addresses.is_empty());
        assert!(config.replies.enabled);
        assert!(config.pyzor_config().is_none(), "Pyzor is off by default");
    }

    #[test]
    fn parses_traps_replies_and_pyzor() {
        let config = Config::parse(
            "[traps]\naddresses = [\"trap@example.org\", \"@bait.example.net\"]\n\
             [replies]\nttl_days = 30\n\
             [pyzor]\nenabled = true\nmin_count = 3\ntimeout_ms = 500\n",
        )
        .unwrap();
        assert_eq!(config.traps.addresses.len(), 2);
        assert_eq!(
            config.reply_config().ttl,
            Duration::from_secs(30 * 24 * 3600)
        );
        let pyzor = config.pyzor_config().unwrap();
        assert_eq!(pyzor.servers, ["public.pyzor.org:24441"]);
        assert_eq!(pyzor.min_count, 3);
        assert_eq!(pyzor.timeout, Duration::from_millis(500));
    }

    #[test]
    fn parses_dns_and_dnsbl() {
        let config = Config::parse(
            "[dns]\nnameservers = [\"127.0.0.1\"]\nhostname = \"mx.example.org\"\n\n\
             [[dnsbl]]\nzone = \"zen.example.org\"\nipv6 = true\n\
             results = [{ codes = [2, 3], symbol = \"RBL_EXAMPLE_SBL\" }]\n",
        )
        .unwrap();
        assert_eq!(
            config.dns.nameservers,
            ["127.0.0.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            config.dns.timeout_ms, 2000,
            "unset keys keep their defaults"
        );
        let zones = config.dnsbl_zones().unwrap();
        assert_eq!(zones[0].zone, "zen.example.org");
        assert!(zones[0].ipv6);
        assert_eq!(zones[0].results.len(), 2);
        assert_eq!(zones[0].results[1].codes, 3..=3);

        let bad = Config::parse(
            "[[dnsbl]]\nzone = \"x.example\"\nresults = [{ codes = [2], symbol = \"bad\" }]\n",
        )
        .unwrap();
        assert!(bad.dnsbl_zones().is_err());
    }

    #[test]
    fn refuses_unknown_keys_and_bad_names() {
        assert!(Config::parse("unknown = 1\n").is_err());
        assert!(Config::parse("[thresholds]\nspam = 1.0\n").is_err());
        let bad = Config::parse("[scores]\nlower = 1.0\n").unwrap();
        assert!(bad.scores(&ScoreTable::new()).is_err());
    }
}
