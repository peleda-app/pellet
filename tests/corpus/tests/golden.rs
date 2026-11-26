//! Every fixture in `fixtures/` through the whole pipeline, over its own DNS records.

use std::sync::Arc;

use pellet_check_auth::{AuthCheck, AuthConfig};
use pellet_check_classifier::{ClassifierCheck, ClassifierConfig, document};
use pellet_check_content::{
    AddressCheck, DateCheck, EncodingCheck, HeaderFlagsCheck, HeaderPresenceCheck, HeadersCheck,
    HtmlCheck, MessageIdCheck, MimeCheck, ReceivedCheck, SubjectCheck,
};
use pellet_check_ip::{
    DnsblCheck, DnsblResult, DnsblZone, FromHostCheck, HeloCheck, ReverseDnsCheck,
};
use pellet_check_pyzor::{PyzorCheck, PyzorConfig};
use pellet_check_reputation::{
    ReplyCheck, ReplyConfig, ReputationCheck, ReputationConfig, TrapCheck,
};
use pellet_check_rules::{DnsListCheck, RulesCheck};
use pellet_check_url::UrlCheck;
use pellet_classifier::{Model, Params};
use pellet_core::{Envelope, Message, Symbol, SymbolName};
use pellet_corpus::{DnsRecords, Fixture, fixtures_dir, load, run};
use pellet_dns::{Resolver, testing::FakeResolver};
use pellet_engine::Engine;
use pellet_rules::RuleSet;
use pellet_state_memory::MemoryState;

/// The time every fixture is checked at: Thu, 12 Mar 2026 12:00:00 +0000.
const CORPUS_NOW: i64 = 1_773_316_800;

fn untrained() -> Model {
    Model::new(Params {
        bits: 16,
        ..Params::default()
    })
    .unwrap()
}

/// The corpus engine's classifier never speaks and never learns, so fixtures stay independent.
fn silent() -> ClassifierConfig {
    ClassifierConfig {
        min_ham: u64::MAX,
        min_spam: u64::MAX,
        auto_learn: false,
        ..ClassifierConfig::default()
    }
}

/// A redirector the fixtures may link through, besides the bundled list.
const TEST_REDIRECTOR: &str = "redirect.example.net";

/// The DNS list every fixture can be listed in: `127.0.0.2` means `RBL_EXAMPLE`.
const DNSBL_ZONE: &str = "dnsbl.example.net";

/// The spam trap address every fixture can write to.
const TRAP: &str = "trap@example.org";

/// The corpus engine for a fixture: its DNS records, the mail it says was sent before, and a fake
/// Pyzor server when it gives Pyzor's answer.
async fn engine(fixture: &Fixture) -> Engine {
    let expectations = &fixture.expectations;
    let replies = Arc::new(ReplyCheck::new(
        Arc::new(MemoryState::new(1000)),
        ReplyConfig::default(),
    ));
    for sent in &expectations.sent {
        let message =
            Message::new(format!("Message-ID: <{}>\r\n\r\n", sent.message_id).into_bytes());
        let envelope = Envelope {
            recipients: sent.recipients.clone(),
            ..Envelope::default()
        };
        assert!(
            replies.record_sent(&message, &envelope).await.unwrap(),
            "{}: sent mail needs a Message-ID and recipients",
            fixture.name
        );
    }
    let pyzor = match expectations.pyzor {
        Some(answer) => {
            vec![pellet_check_pyzor::testing::serve(answer.count, answer.whitelist).await]
        }
        None => Vec::new(),
    };
    engine_over(&expectations.dns, replies, pyzor)
}

fn engine_over(dns: &DnsRecords, replies: Arc<ReplyCheck>, pyzor: Vec<String>) -> Engine {
    let mut fake = FakeResolver::new();
    for (name, ips) in &dns.a {
        fake = fake.with_ipv4(name, &ips.iter().map(String::as_str).collect::<Vec<_>>());
    }
    for (name, ips) in &dns.aaaa {
        fake = fake.with_ipv6(name, &ips.iter().map(String::as_str).collect::<Vec<_>>());
    }
    for (name, records) in &dns.txt {
        fake = fake.with_txt(
            name,
            &records.iter().map(String::as_str).collect::<Vec<_>>(),
        );
    }
    for (name, records) in &dns.mx {
        let parsed: Vec<(u16, &str)> = records
            .iter()
            .map(|r| {
                let (preference, host) = r.split_once(' ').expect("mx is \"<preference> <host>\"");
                (preference.parse().expect("mx preference"), host)
            })
            .collect();
        fake = fake.with_mx(name, &parsed);
    }
    for (ip, names) in &dns.ptr {
        fake = fake.with_ptr(ip, &names.iter().map(String::as_str).collect::<Vec<_>>());
    }
    let resolver: Arc<dyn Resolver> = Arc::new(fake);

    let auth = AuthCheck::new(&AuthConfig {
        nameservers: vec!["192.0.2.53".parse().unwrap()],
        hostname: "mx.example.org".into(),
        ..AuthConfig::default()
    })
    .unwrap();
    for (name, records) in &dns.txt {
        for record in records {
            auth.add_txt_record(name, record);
        }
    }

    let dnsbl = DnsblZone {
        zone: DNSBL_ZONE.into(),
        ipv6: true,
        results: vec![DnsblResult {
            codes: 2..=2,
            symbol: SymbolName::new("RBL_EXAMPLE").unwrap(),
        }],
    };
    let rules = Arc::new(RuleSet::bundled().unwrap());
    Engine::builder()
        .check(Arc::new(DnsblCheck::new(resolver.clone(), vec![dnsbl])))
        .check(Arc::new(ReverseDnsCheck::new(resolver.clone())))
        .check(Arc::new(HeloCheck::new(resolver.clone())))
        .check(Arc::new(FromHostCheck::new(resolver.clone())))
        .check(Arc::new(HeadersCheck::new()))
        .check(Arc::new(HeaderPresenceCheck::from_symbols(
            rules.referenced_symbols(),
        )))
        .check(Arc::new(HeaderFlagsCheck::new()))
        .check(Arc::new(AddressCheck::new().alias_domains(
            rules.lists().entries("alias-relays").map(|(d, _)| d),
        )))
        .check(Arc::new(EncodingCheck::new()))
        .check(Arc::new(MessageIdCheck::new()))
        .check(Arc::new(DateCheck::with_clock(|| CORPUS_NOW)))
        .check(Arc::new(ReceivedCheck::new()))
        .check(Arc::new(SubjectCheck::new()))
        .check(Arc::new(MimeCheck::new(
            rules.lists().entries("file-extensions"),
        )))
        .check(Arc::new(HtmlCheck::new()))
        .check(Arc::new(
            UrlCheck::new(
                rules
                    .lists()
                    .entries("url-redirectors")
                    .map(|(host, _)| host)
                    .chain([TEST_REDIRECTOR]),
            )
            .click_trackers(rules.lists().entries("click-trackers").map(|(h, _)| h)),
        ))
        .check(Arc::new(auth))
        .check(Arc::new(RulesCheck::new(rules.clone())))
        .check(Arc::new(DnsListCheck::new(rules, resolver.clone())))
        .check(Arc::new(ClassifierCheck::new(untrained(), silent())))
        .check(Arc::new(ReputationCheck::new(
            Arc::new(MemoryState::new(1000)),
            ReputationConfig::default(),
        )))
        .check(Arc::new(TrapCheck::new([TRAP])))
        .check(replies)
        .check(Arc::new(PyzorCheck::new(PyzorConfig {
            servers: pyzor,
            ..PyzorConfig::default()
        })))
        .build()
        .expect("corpus engine")
}

#[tokio::test]
async fn corpus() {
    let fixtures = load(&fixtures_dir());
    assert!(!fixtures.is_empty(), "the corpus is empty");
    let mut problems = Vec::new();
    for fixture in &fixtures {
        assert!(
            !fixture.expectations.expect.is_empty() || !fixture.expectations.absent.is_empty(),
            "{} checks nothing",
            fixture.name
        );
        problems.extend(run(&engine(fixture).await, fixture).await.1);
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}

#[tokio::test]
async fn harness_reports_broken_expectations() {
    let mut fixture = load(&fixtures_dir()).remove(0);
    fixture.expectations.expect = vec!["NEVER_FIRES".into()];
    let (_, problems) = run(&engine(&fixture).await, &fixture).await;
    assert_eq!(
        problems,
        [format!("{}: expected NEVER_FIRES", fixture.name)]
    );
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Deferred {
    group: Vec<DeferredGroup>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeferredGroup {
    reason: String,
    symbols: Vec<String>,
}

/// Every scored symbol is either declared by a registered check or listed in `deferred.toml`
/// with a reason, and nothing listed there is declared already.
#[test]
fn every_scored_symbol_is_covered_or_deferred() {
    let replies = Arc::new(ReplyCheck::new(
        Arc::new(MemoryState::new(10)),
        ReplyConfig::default(),
    ));
    let declared: std::collections::BTreeSet<String> =
        engine_over(&DnsRecords::default(), replies, Vec::new())
            .declared_symbols()
            .into_iter()
            .map(|s| s.to_string())
            .collect();
    let rules = RuleSet::bundled().unwrap();
    let scored: std::collections::BTreeSet<String> =
        rules.scores().names().map(|s| s.to_string()).collect();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("deferred.toml");
    let deferred: Deferred = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let mut listed = std::collections::BTreeSet::new();
    for group in &deferred.group {
        assert!(!group.reason.is_empty());
        for symbol in &group.symbols {
            assert!(listed.insert(symbol.clone()), "{symbol} is listed twice");
            assert!(
                scored.contains(symbol),
                "{symbol} is listed but has no score"
            );
            assert!(
                !declared.contains(symbol),
                "{symbol} is implemented now; remove it from deferred.toml"
            );
        }
    }
    let uncovered: Vec<&String> = scored
        .iter()
        .filter(|s| !declared.contains(*s) && !listed.contains(*s))
        .collect();
    assert!(
        uncovered.is_empty(),
        "neither implemented nor deferred: {uncovered:?}"
    );
}

/// A model trained on the labeled fixtures, with the symbols the other checks gave them,
/// puts every one of them on the right side.
#[tokio::test]
async fn classifier_separates_the_corpus() {
    let fixtures: Vec<Fixture> = load(&fixtures_dir())
        .into_iter()
        .filter(|f| f.expectations.label.is_some())
        .collect();
    let spam_count = fixtures
        .iter()
        .filter(|f| f.expectations.label.as_deref() == Some("spam"))
        .count();
    assert!(
        spam_count >= 5 && fixtures.len() - spam_count >= 5,
        "too few labeled fixtures"
    );

    let mut samples = Vec::new();
    for fixture in &fixtures {
        let verdict = run(&engine(fixture).await, fixture).await.0;
        let symbols: Vec<Symbol> = verdict
            .symbols
            .into_iter()
            .map(|s| Symbol::new(s.name))
            .collect();
        let doc = document(&fixture.message, &fixture.expectations.envelope, &symbols);
        let spam = match fixture.expectations.label.as_deref() {
            Some("spam") => true,
            Some("ham") => false,
            other => panic!("{}: label must be spam or ham, not {other:?}", fixture.name),
        };
        samples.push((fixture.name.clone(), doc, spam));
    }
    let mut model = untrained();
    for _ in 0..5 {
        for (_, doc, spam) in &samples {
            model.train(doc, *spam);
        }
    }
    assert!(model.memory_bytes() <= 2 * 1024 * 1024);
    let wrong: Vec<String> = samples
        .iter()
        .filter(|(_, doc, spam)| (model.predict(doc) > 0.5) != *spam)
        .map(|(name, doc, _)| format!("{name}: {:.2}", model.predict(doc)))
        .collect();
    assert!(wrong.is_empty(), "misjudged: {wrong:?}");
}
