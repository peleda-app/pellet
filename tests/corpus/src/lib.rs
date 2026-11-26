//! Golden tests: hand-written messages in `fixtures/` and the symbols Pellet must emit for them.
//!
//! Each fixture is a pair: `<name>.eml` holds the message, `<name>.toml` holds the envelope, the
//! DNS records the checks may look up, and the expectations. The golden test in `tests/` builds an
//! engine with every check over those records, the way the binary does, and runs the whole
//! pipeline on each pair without touching the network.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use pellet_core::{Envelope, Message, Verdict};
use pellet_engine::Engine;
use serde::Deserialize;

/// The expectations in `<name>.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Expectations {
    /// What the message represents.
    pub description: String,
    /// The SMTP envelope.
    pub envelope: Envelope,
    /// DNS records; every other name does not exist.
    pub dns: DnsRecords,
    /// Symbols that must fire.
    pub expect: Vec<String>,
    /// Symbols that must not fire.
    pub absent: Vec<String>,
    /// `spam` or `ham`, for the classifier test; unlabeled fixtures are left out of it.
    pub label: Option<String>,
    /// Messages the deployment sent before this one arrived, so replies to them are recognized.
    pub sent: Vec<Sent>,
    /// What a fake Pyzor server answers about this message; without it Pyzor is not asked.
    pub pyzor: Option<PyzorAnswer>,
}

/// A message the deployment sent earlier.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Sent {
    /// Its Message-ID, without angle brackets.
    pub message_id: String,
    /// Its envelope recipients.
    pub recipients: Vec<String>,
}

/// A Pyzor server's counts for a digest.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PyzorAnswer {
    /// Spam reports.
    pub count: u64,
    /// Whitelist entries.
    pub whitelist: u64,
}

/// DNS records of a fixture, by name (by address for `ptr`).
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsRecords {
    /// A records.
    pub a: BTreeMap<String, Vec<String>>,
    /// AAAA records.
    pub aaaa: BTreeMap<String, Vec<String>>,
    /// TXT records, including SPF, DKIM keys and DMARC.
    pub txt: BTreeMap<String, Vec<String>>,
    /// MX records as `"<preference> <host>"`.
    pub mx: BTreeMap<String, Vec<String>>,
    /// PTR records by address.
    pub ptr: BTreeMap<String, Vec<String>>,
}

/// One message and its expectations.
#[derive(Debug)]
pub struct Fixture {
    /// The file stem shared by both files.
    pub name: String,
    /// The parsed message.
    pub message: Message,
    /// What must and must not fire.
    pub expectations: Expectations,
}

/// The directory holding the fixtures.
pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// Every fixture in `dir`, sorted by name.
///
/// # Panics
///
/// Panics on an unreadable file, a `.eml` without its `.toml` or the other way round, or invalid
/// TOML; a broken corpus must fail loudly.
pub fn load(dir: &Path) -> Vec<Fixture> {
    let mut stems: Vec<String> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter_map(|path| {
            let ext = path.extension()?.to_str()?;
            assert!(
                matches!(ext, "eml" | "toml"),
                "unexpected file {}",
                path.display()
            );
            Some(path.file_stem()?.to_str()?.to_string())
        })
        .collect();
    stems.sort();
    stems.dedup();
    stems
        .into_iter()
        .map(|name| {
            let eml = dir.join(format!("{name}.eml"));
            let toml_path = dir.join(format!("{name}.toml"));
            let raw = std::fs::read(&eml).unwrap_or_else(|e| panic!("{}: {e}", eml.display()));
            let text = std::fs::read_to_string(&toml_path)
                .unwrap_or_else(|e| panic!("{}: {e}", toml_path.display()));
            let expectations =
                toml::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", toml_path.display()));
            Fixture {
                name,
                message: Message::new(raw),
                expectations,
            }
        })
        .collect()
}

/// Runs a fixture and returns every broken expectation; empty when it passes.
pub async fn run(engine: &Engine, fixture: &Fixture) -> (Verdict, Vec<String>) {
    let verdict = engine
        .check_message(
            fixture.expectations.envelope.clone(),
            fixture.message.clone(),
        )
        .await;
    let mut problems = Vec::new();
    for name in &fixture.expectations.expect {
        if !verdict.has(name) {
            problems.push(format!("{}: expected {name}", fixture.name));
        }
    }
    for name in &fixture.expectations.absent {
        if verdict.has(name) {
            problems.push(format!("{}: unexpected {name}", fixture.name));
        }
    }
    for failure in &verdict.failures {
        problems.push(format!("{}: check {} failed", fixture.name, failure.check));
    }
    (verdict, problems)
}
