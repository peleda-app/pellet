//! SPF, DKIM, DMARC and ARC verification emitted as symbols.
//!
//! Verification is done by `mail-auth`, which resolves through its own hickory resolver; answers
//! are kept in a bounded cache owned by the check.

mod cache;

use std::{net::IpAddr, time::Duration};

use async_trait::async_trait;
use mail_auth::{
    AuthenticatedMessage, DkimResult, DmarcResult, MessageAuthenticator, Parameters, SpfOutput,
    SpfResult,
    dmarc::{Policy, verify::DmarcParameters},
    hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts},
    spf::verify::SpfParameters,
};
use pellet_check::{Check, CheckError, Context, symbol_names};
use pellet_core::{Envelope, Stage, Symbol, SymbolName};

use crate::cache::AuthCache;

const SYMBOLS: [&str; 27] = [
    "SPF_ALLOW",
    "SPF_FAIL",
    "SPF_SOFTFAIL",
    "SPF_NEUTRAL",
    "SPF_NA",
    "SPF_DNSFAIL",
    "SPF_PERMFAIL",
    "DKIM_SIGNED",
    "DKIM_ALLOW",
    "DKIM_REJECT",
    "DKIM_TEMPFAIL",
    "DKIM_PERMFAIL",
    "DKIM_NA",
    "ARC_SIGNED",
    "ARC_ALLOW",
    "ARC_REJECT",
    "ARC_INVALID",
    "ARC_DNSFAIL",
    "ARC_NA",
    "DMARC_POLICY_ALLOW",
    "DMARC_POLICY_REJECT",
    "DMARC_POLICY_QUARANTINE",
    "DMARC_POLICY_SOFTFAIL",
    "DMARC_NA",
    "DMARC_DNSFAIL",
    "DMARC_BAD_POLICY",
    "AUTH_NA",
];

/// How the check reaches DNS and names itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfig {
    /// Recursive resolvers on port 53; empty means the system configuration.
    pub nameservers: Vec<IpAddr>,
    /// This server's host name, used by SPF macros.
    pub hostname: String,
    /// Most answers kept per record type.
    pub cache_entries: usize,
    /// Longest wait for one DNS answer.
    pub dns_timeout: Duration,
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            nameservers: Vec::new(),
            hostname: "localhost".into(),
            cache_entries: 2048,
            dns_timeout: Duration::from_secs(2),
        }
    }
}

/// The resolver for the check could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot build the authentication resolver: {0}")]
pub struct BuildError(String);

/// SPF, DKIM, ARC and DMARC at [`Stage::Data`].
///
/// | Symbols | When |
/// | --- | --- |
/// | `SPF_ALLOW`, `SPF_FAIL`, `SPF_SOFTFAIL`, `SPF_NEUTRAL`, `SPF_NA`, `SPF_DNSFAIL`, `SPF_PERMFAIL` | SPF result for `MAIL FROM`, or for HELO with a null sender; needs the client address; option: the domain |
/// | `DKIM_SIGNED` | the message carries DKIM signatures; options: signing domains |
/// | `DKIM_ALLOW` | a signature verified; options: its domains |
/// | `DKIM_REJECT` | a signature failed or does not match the body |
/// | `DKIM_TEMPFAIL`, `DKIM_PERMFAIL` | a key lookup failed temporarily, or the key is missing or invalid |
/// | `DKIM_NA` | no signatures |
/// | `ARC_SIGNED`, `ARC_ALLOW`, `ARC_REJECT`, `ARC_INVALID`, `ARC_DNSFAIL` | an ARC chain exists, and how it validated |
/// | `ARC_NA` | no ARC chain |
/// | `DMARC_POLICY_ALLOW` | DMARC passed; option: the From domain |
/// | `DMARC_POLICY_REJECT`, `DMARC_POLICY_QUARANTINE`, `DMARC_POLICY_SOFTFAIL` | DMARC failed under policy `reject`, `quarantine`, or `none` |
/// | `DMARC_NA`, `DMARC_DNSFAIL`, `DMARC_BAD_POLICY` | no DMARC record or no From domain; a lookup failed; the record is broken |
/// | `AUTH_NA` | none of SPF, DKIM and DMARC apply |
///
/// Skipped for authenticated clients. A message `mail-auth` cannot parse gets `DKIM_NA`,
/// `ARC_NA` and `DMARC_NA`.
pub struct AuthCheck {
    authenticator: MessageAuthenticator,
    cache: AuthCache,
    hostname: String,
    declared: Vec<SymbolName>,
}

impl AuthCheck {
    /// Builds the check; nothing is queried until the first message.
    pub fn new(config: &AuthConfig) -> Result<Self, BuildError> {
        let authenticator = if config.nameservers.is_empty() {
            MessageAuthenticator::new_system_conf()
        } else {
            let servers = config
                .nameservers
                .iter()
                .map(|ip| NameServerConfig::udp_and_tcp(*ip))
                .collect();
            let mut options = ResolverOpts::default();
            options.timeout = config.dns_timeout;
            options.cache_size = 0;
            MessageAuthenticator::new(ResolverConfig::from_name_servers(servers), options)
        }
        .map_err(|e| BuildError(e.to_string()))?;
        Ok(AuthCheck {
            authenticator,
            cache: AuthCache::new(config.cache_entries),
            hostname: config.hostname.clone(),
            declared: symbol_names(&SYMBOLS),
        })
    }

    /// Puts a TXT record (SPF, DKIM key or DMARC, told apart by its contents) into the cache for
    /// an hour, so tests can verify without DNS. With the `testing` feature every lookup that
    /// misses the cache answers "no such name".
    #[cfg(any(test, feature = "testing"))]
    pub fn add_txt_record(&self, name: &str, record: &str) {
        use mail_auth::{
            ResolverCache, TxtRecord,
            dkim::DomainKey,
            dmarc::DmarcRecord,
            dns::{ToFqdn, TxtRecordParser},
            spf::SpfRecord,
        };
        let bytes = record.as_bytes();
        let parsed: TxtRecord = if record.starts_with("v=spf1") {
            SpfRecord::parse(bytes).into()
        } else if record.starts_with("v=DMARC1") {
            DmarcRecord::parse(bytes).into()
        } else {
            DomainKey::parse(bytes).into()
        };
        self.cache.txt.insert(
            name.to_fqdn().into_owned().into_boxed_str(),
            parsed,
            std::time::Instant::now() + Duration::from_secs(3600),
        );
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

    async fn spf(&self, envelope: &Envelope) -> Option<SpfOutput> {
        let ip = envelope.client_ip?;
        let helo = envelope.helo.as_deref().unwrap_or_default();
        let params = match envelope.mail_from.as_deref() {
            Some(sender) if !sender.is_empty() => {
                SpfParameters::mail_from(ip, helo, &self.hostname, sender)
            }
            _ => SpfParameters::helo(ip, helo, &self.hostname),
        };
        Some(
            self.authenticator
                .verify_spf(Parameters::new(params).with_cache(&self.cache))
                .await,
        )
    }

    fn spf_symbol(&self, output: &SpfOutput) -> Symbol {
        let name = match output.result() {
            SpfResult::Pass => "SPF_ALLOW",
            SpfResult::Fail => "SPF_FAIL",
            SpfResult::SoftFail => "SPF_SOFTFAIL",
            SpfResult::Neutral => "SPF_NEUTRAL",
            SpfResult::None => "SPF_NA",
            SpfResult::TempError => "SPF_DNSFAIL",
            SpfResult::PermError => "SPF_PERMFAIL",
        };
        let symbol = self.symbol(name);
        if output.domain().is_empty() {
            symbol
        } else {
            symbol.with_option(output.domain().to_ascii_lowercase())
        }
    }
}

fn mail_from_domain(envelope: &Envelope) -> &str {
    match envelope.mail_from.as_deref() {
        Some(sender) if !sender.is_empty() => {
            sender.rsplit_once('@').map_or(sender, |(_, domain)| domain)
        }
        _ => envelope.helo.as_deref().unwrap_or_default(),
    }
}

#[async_trait]
impl Check for AuthCheck {
    fn name(&self) -> &str {
        "auth"
    }

    fn stage(&self) -> Stage {
        Stage::Data
    }

    fn symbols(&self) -> &[SymbolName] {
        &self.declared
    }

    async fn run(&self, ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError> {
        if ctx.envelope.authenticated {
            return Ok(Vec::new());
        }
        let raw = ctx
            .message
            .ok_or_else(|| CheckError::Failed("no message at the data stage".into()))?
            .raw();
        let mut out = Vec::new();

        let spf = self.spf(ctx.envelope).await;
        if let Some(spf) = &spf {
            out.push(self.spf_symbol(spf));
        }
        let spf_na = spf.as_ref().is_none_or(|s| s.result() == SpfResult::None);

        let Some(message) = AuthenticatedMessage::parse(raw) else {
            out.push(self.symbol("DKIM_NA"));
            out.push(self.symbol("ARC_NA"));
            out.push(self.symbol("DMARC_NA"));
            if spf_na {
                out.push(self.symbol("AUTH_NA"));
            }
            return Ok(out);
        };

        let dkim = self
            .authenticator
            .verify_dkim(Parameters::new(&message).with_cache(&self.cache))
            .await;
        if dkim.is_empty() {
            out.push(self.symbol("DKIM_NA"));
        } else {
            let mut signed = self.symbol("DKIM_SIGNED");
            let mut allow = self.symbol("DKIM_ALLOW");
            let (mut reject, mut temp, mut perm) = (false, false, false);
            for output in &dkim {
                let domain = output.signature().map(|s| s.d.to_ascii_lowercase());
                if let Some(domain) = &domain
                    && !signed.options.contains(domain)
                {
                    signed.push_option(domain.clone());
                }
                match output.result() {
                    DkimResult::Pass => {
                        if let Some(domain) = domain
                            && !allow.options.contains(&domain)
                        {
                            allow.push_option(domain);
                        }
                    }
                    DkimResult::Fail(_) | DkimResult::Neutral(_) => reject = true,
                    DkimResult::TempError(_) => temp = true,
                    DkimResult::PermError(_) => perm = true,
                    DkimResult::None => {}
                }
            }
            let passed = dkim.iter().any(|o| o.result() == &DkimResult::Pass);
            out.push(signed);
            if passed {
                out.push(allow);
            }
            for (flag, name) in [
                (reject, "DKIM_REJECT"),
                (temp, "DKIM_TEMPFAIL"),
                (perm, "DKIM_PERMFAIL"),
            ] {
                if flag {
                    out.push(self.symbol(name));
                }
            }
        }

        let arc = self
            .authenticator
            .verify_arc(Parameters::new(&message).with_cache(&self.cache))
            .await;
        if !arc.chain().is_empty() {
            out.push(self.symbol("ARC_SIGNED"));
        }
        match arc.result() {
            DkimResult::None => out.push(self.symbol("ARC_NA")),
            DkimResult::Pass => out.push(self.symbol("ARC_ALLOW")),
            DkimResult::Fail(_) => out.push(self.symbol("ARC_REJECT")),
            DkimResult::Neutral(_) | DkimResult::PermError(_) => {
                out.push(self.symbol("ARC_INVALID"))
            }
            DkimResult::TempError(_) => out.push(self.symbol("ARC_DNSFAIL")),
        }

        let no_spf = SpfOutput::default();
        let dmarc = self
            .authenticator
            .verify_dmarc(
                Parameters::new(DmarcParameters::new(
                    &message,
                    &dkim,
                    mail_from_domain(ctx.envelope),
                    spf.as_ref().unwrap_or(&no_spf),
                ))
                .with_cache(&self.cache),
            )
            .await;
        let dmarc_symbol = match dmarc.result() {
            DmarcResult::Pass => "DMARC_POLICY_ALLOW",
            DmarcResult::Fail(_) => match dmarc.policy() {
                Policy::Reject => "DMARC_POLICY_REJECT",
                Policy::Quarantine => "DMARC_POLICY_QUARANTINE",
                Policy::None | Policy::Unspecified => "DMARC_POLICY_SOFTFAIL",
            },
            DmarcResult::TempError(_) => "DMARC_DNSFAIL",
            DmarcResult::PermError(_) => "DMARC_BAD_POLICY",
            DmarcResult::None => "DMARC_NA",
        };
        let mut symbol = self.symbol(dmarc_symbol);
        if !dmarc.domain().is_empty() {
            symbol.push_option(dmarc.domain().to_ascii_lowercase());
        }
        out.push(symbol);

        if spf_na && dkim.is_empty() && dmarc_symbol == "DMARC_NA" {
            out.push(self.symbol("AUTH_NA"));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
