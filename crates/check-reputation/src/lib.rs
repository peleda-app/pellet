//! Sender and client address reputation, spam traps and replies to sent mail, kept in Pellet
//! state.

mod reply;
mod trap;

use std::{
    net::{IpAddr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use pellet_check::{Check, CheckError, Context, symbol_names};
use pellet_core::{Envelope, Stage, Symbol, SymbolName};
use pellet_dns::{is_listable, normalize};
use pellet_state::{Expect, Key, State, StateError};

pub use reply::{ReplyCheck, ReplyConfig};
pub use trap::TrapCheck;

/// How reputation is counted and judged.
#[derive(Debug, Clone, PartialEq)]
pub struct ReputationConfig {
    /// Samples an address or domain needs before it is judged.
    pub min_samples: u32,
    /// Share of spam at or above which it counts as spammy.
    pub spam_ratio: f64,
    /// Share of spam at or below which it counts as clean.
    pub ham_ratio: f64,
    /// How long counts live after their last update.
    pub ttl: Duration,
    /// Symbol name prefixes that count as blocklist hits when learning by itself.
    pub blocklists: Vec<String>,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        ReputationConfig {
            min_samples: 5,
            spam_ratio: 0.8,
            ham_ratio: 0.2,
            ttl: Duration::from_secs(30 * 24 * 3600),
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

/// Counts of ham and spam seen for one address or domain.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Messages judged ham.
    pub ham: u32,
    /// Messages judged spam.
    pub spam: u32,
}

impl Counts {
    fn decode(bytes: &[u8]) -> Counts {
        match bytes {
            [a, b, c, d, e, f, g, h] => Counts {
                ham: u32::from_le_bytes([*a, *b, *c, *d]),
                spam: u32::from_le_bytes([*e, *f, *g, *h]),
            },
            _ => Counts::default(),
        }
    }

    fn encode(self) -> Vec<u8> {
        let mut out = self.ham.to_le_bytes().to_vec();
        out.extend_from_slice(&self.spam.to_le_bytes());
        out
    }

    fn total(self) -> u32 {
        self.ham.saturating_add(self.spam)
    }
}

/// Reputation of the client address and the authenticated From domain, at [`Stage::Data`]
/// after the other checks of the stage.
///
/// | Symbol | When |
/// | --- | --- |
/// | `REPUTATION_IP_SPAM`, `REPUTATION_IP_HAM` | the client address (IPv6 by its /64) has enough samples and a spam share at or above `spam_ratio`, or at or below `ham_ratio` |
/// | `REPUTATION_DOMAIN_SPAM`, `REPUTATION_DOMAIN_HAM` | the same for the From domain, only when `DMARC_POLICY_ALLOW` vouches for it |
///
/// The option is `spam/total`. Counts live in [`State`] under `rep/ip/…` and `rep/domain/…` as
/// eight bytes, for `ttl` after their last update. After judging, an unauthenticated message
/// updates the counts by itself when the signals are strong: spam for a blocklist hit together
/// with `DMARC_POLICY_REJECT`, `DMARC_POLICY_QUARANTINE` or `SPF_FAIL`, or for `GTUBE_TEST` or
/// `SPAM_TRAP`; ham
/// when `DKIM_ALLOW`, `SPF_ALLOW` and `DMARC_POLICY_ALLOW` all fired without a blocklist hit.
/// [`ReputationCheck::learn`] takes feedback. State failures leave the message unjudged and
/// uncounted; they never fail the check.
pub struct ReputationCheck {
    state: Arc<dyn State>,
    config: ReputationConfig,
    declared: Vec<SymbolName>,
}

fn ip_key(ip: IpAddr) -> Option<Key> {
    if !is_listable(ip) {
        return None;
    }
    let ip = match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
        v4 => v4,
    };
    Key::new(format!("rep/ip/{ip}")).ok()
}

fn domain_key(domain: &str) -> Option<Key> {
    Key::new(format!("rep/domain/{}", normalize(domain).ok()?)).ok()
}

impl ReputationCheck {
    /// Builds the check over a state store.
    pub fn new(state: Arc<dyn State>, config: ReputationConfig) -> Self {
        ReputationCheck {
            state,
            config,
            declared: symbol_names(&[
                "REPUTATION_IP_SPAM",
                "REPUTATION_IP_HAM",
                "REPUTATION_DOMAIN_SPAM",
                "REPUTATION_DOMAIN_HAM",
            ]),
        }
    }

    fn keys(&self, envelope: &Envelope, symbols: &[Symbol]) -> Vec<(&'static str, Key)> {
        let mut keys = Vec::new();
        if let Some(key) = envelope.client_ip.and_then(ip_key) {
            keys.push(("IP", key));
        }
        if let Some(key) = symbols
            .iter()
            .find(|s| s.name.as_str() == "DMARC_POLICY_ALLOW")
            .and_then(|s| s.options.first())
            .and_then(|d| domain_key(d))
        {
            keys.push(("DOMAIN", key));
        }
        keys
    }

    /// The counts kept for a key; zero when there are none or the state is unavailable.
    pub async fn counts(&self, key: &Key) -> Counts {
        match self.state.get(key).await {
            Ok(Some(entry)) => Counts::decode(&entry.value),
            _ => Counts::default(),
        }
    }

    async fn add(&self, key: &Key, spam: bool) -> Result<(), StateError> {
        for _ in 0..3 {
            let current = self.state.get(key).await?;
            let mut counts = current
                .as_ref()
                .map(|e| Counts::decode(&e.value))
                .unwrap_or_default();
            if spam {
                counts.spam = counts.spam.saturating_add(1);
            } else {
                counts.ham = counts.ham.saturating_add(1);
            }
            let expect = current.map_or(Expect::Absent, |e| Expect::Version(e.version));
            match self
                .state
                .put(key, counts.encode(), expect, Some(self.config.ttl))
                .await
            {
                Err(StateError::Conflict) => continue,
                other => return other.map(|_| ()),
            }
        }
        Err(StateError::Conflict)
    }

    /// Counts a message a person marked, with the symbols the other checks gave it.
    pub async fn learn(&self, envelope: &Envelope, symbols: &[Symbol], spam: bool) {
        for (_, key) in self.keys(envelope, symbols) {
            let _ = self.add(&key, spam).await;
        }
    }

    fn judge(&self, kind: &str, counts: Counts) -> Option<Symbol> {
        let total = counts.total();
        if total < self.config.min_samples || total == 0 {
            return None;
        }
        let share = f64::from(counts.spam) / f64::from(total);
        let verdict = if share >= self.config.spam_ratio {
            "SPAM"
        } else if share <= self.config.ham_ratio {
            "HAM"
        } else {
            return None;
        };
        let name = format!("REPUTATION_{kind}_{verdict}");
        let declared = self.declared.iter().find(|d| d.as_str() == name)?;
        Some(Symbol::new(declared.clone()).with_option(format!("{}/{total}", counts.spam)))
    }

    fn strong_label(&self, ctx: &Context<'_>) -> Option<bool> {
        if ctx.envelope.authenticated {
            return None;
        }
        let blocklisted = ctx.earlier.iter().any(|s| {
            self.config
                .blocklists
                .iter()
                .any(|p| s.name.as_str().starts_with(p.as_str()))
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

#[async_trait]
impl Check for ReputationCheck {
    fn name(&self) -> &str {
        "reputation"
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
        let keys = self.keys(ctx.envelope, ctx.earlier);
        let mut out = Vec::new();
        for (kind, key) in &keys {
            if let Some(symbol) = self.judge(kind, self.counts(key).await) {
                out.push(symbol);
            }
        }
        if let Some(spam) = self.strong_label(ctx) {
            for (_, key) in &keys {
                let _ = self.add(key, spam).await;
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
