use pellet_check::testing::{Fixture, conformance};
use pellet_classifier::Params;

use super::*;

const SPAM_WORDS: [&str; 8] = [
    "winner", "prize", "casino", "bonus", "claim", "free", "cheap", "loan",
];
const HAM_WORDS: [&str; 8] = [
    "meeting", "report", "agenda", "draft", "notes", "review", "budget", "slides",
];

fn raw(i: usize, spam: bool) -> String {
    let words = if spam { SPAM_WORDS } else { HAM_WORDS };
    let pick = |k: usize| words[(i * 3 + k) % words.len()];
    let (from, link) = if spam {
        ("promo@offer.example.net", "https://offer.example.net/x")
    } else {
        ("ana@example.com", "https://intranet.example.com/doc")
    };
    format!(
        "From: {from}\r\nTo: bo@example.org\r\nSubject: {} {}\r\n\r\nPlease look at the {} and the {} for this week, see {link} for the {}.\r\n",
        pick(0),
        pick(1),
        pick(2),
        pick(3),
        pick(4)
    )
}

fn message(i: usize, spam: bool) -> Message {
    Message::new(raw(i, spam).into_bytes())
}

fn small() -> Model {
    Model::new(Params {
        bits: 16,
        ..Params::default()
    })
    .unwrap()
}

fn config(min: u64) -> ClassifierConfig {
    ClassifierConfig {
        min_ham: min,
        min_spam: min,
        ..ClassifierConfig::default()
    }
}

fn trained(min: u64) -> ClassifierCheck {
    let check = ClassifierCheck::new(small(), config(min));
    for i in 0..60 {
        check.learn(&message(i, true), &Envelope::default(), &[], true);
        check.learn(&message(i, false), &Envelope::default(), &[], false);
    }
    check
}

async fn run(check: &ClassifierCheck, fixture: &Fixture) -> Vec<Symbol> {
    check.run(&fixture.context(Stage::Data)).await.unwrap()
}

fn fixture(raw: String) -> Fixture {
    Fixture {
        message: Some(Message::new(raw.into_bytes())),
        ..Fixture::default()
    }
}

#[tokio::test]
async fn trained_model_names_spam_and_ham() {
    let check = trained(50);
    let spam = run(&check, &fixture(raw(1000, true))).await;
    let p: f64 = spam[0].options[0].parse().unwrap();
    assert!(
        p >= 0.8 && spam[0].name.as_str().starts_with("PROB_SPAM_"),
        "{spam:?}"
    );
    let ham = run(&check, &fixture(raw(1001, false))).await;
    let p: f64 = ham[0].options[0].parse().unwrap();
    assert!(
        p <= 0.2 && ham[0].name.as_str().starts_with("PROB_HAM_"),
        "{ham:?}"
    );
    assert_eq!(check.updates(), 120);
    assert_eq!(check.samples(), (60, 60));
}

#[tokio::test]
async fn silent_until_both_classes_have_enough_samples() {
    let check = ClassifierCheck::new(small(), config(5));
    for i in 0..10 {
        check.learn(&message(i, true), &Envelope::default(), &[], true);
    }
    assert!(run(&check, &fixture(raw(99, true))).await.is_empty());
    for i in 0..5 {
        check.learn(&message(i, false), &Envelope::default(), &[], false);
    }
    assert_eq!(run(&check, &fixture(raw(99, true))).await.len(), 1);
}

#[test]
fn bands() {
    for (p, name) in [
        (0.99, "PROB_SPAM_HIGH"),
        (0.95, "PROB_SPAM_HIGH"),
        (0.9, "PROB_SPAM_MEDIUM"),
        (0.7, "PROB_SPAM_LOW"),
        (0.5, "PROB_SPAM_UNCERTAIN"),
        (0.3, "PROB_HAM_LOW"),
        (0.1, "PROB_HAM_MEDIUM"),
        (0.01, "PROB_HAM_HIGH"),
    ] {
        assert_eq!(band(p), name, "{p}");
    }
}

fn with_symbols(raw: String, names: &[&str]) -> Fixture {
    let mut fixture = fixture(raw);
    fixture.earlier = names
        .iter()
        .map(|n| Symbol::new(SymbolName::new(n).unwrap()))
        .collect();
    fixture
}

#[tokio::test]
async fn auto_learns_from_strong_signals() {
    let check = ClassifierCheck::new(small(), config(1000));
    run(
        &check,
        &with_symbols(raw(1, true), &["RBL_SPAMHAUS_SBL", "DMARC_POLICY_REJECT"]),
    )
    .await;
    run(&check, &with_symbols(raw(2, true), &["GTUBE_TEST"])).await;
    run(
        &check,
        &with_symbols(
            raw(3, false),
            &["DKIM_ALLOW", "SPF_ALLOW", "DMARC_POLICY_ALLOW"],
        ),
    )
    .await;
    assert_eq!(check.snapshot().samples(), (1, 2));

    run(&check, &with_symbols(raw(4, true), &["RBL_SPAMHAUS_SBL"])).await;
    run(
        &check,
        &with_symbols(
            raw(5, false),
            &[
                "DKIM_ALLOW",
                "SPF_ALLOW",
                "DMARC_POLICY_ALLOW",
                "URIBL_BLACK",
            ],
        ),
    )
    .await;
    assert_eq!(
        check.snapshot().samples(),
        (1, 2),
        "weak or mixed signals teach nothing"
    );

    let mut submission = with_symbols(raw(6, true), &["GTUBE_TEST"]);
    submission.envelope.authenticated = true;
    run(&check, &submission).await;
    let quiet = ClassifierCheck::new(
        small(),
        ClassifierConfig {
            auto_learn: false,
            ..config(1000)
        },
    );
    run(&quiet, &with_symbols(raw(7, true), &["GTUBE_TEST"])).await;
    assert_eq!(check.snapshot().samples(), (1, 2));
    assert_eq!(quiet.snapshot().samples(), (0, 0));
}

#[test]
fn documents_read_the_message() {
    let html = "From: Shop <deals@shop.example.net>\r\nSubject: Big =?utf-8?q?sale?=\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Save <b>today</b> at <a href=\"https://www.shop.example.net/x\">our shop</a></p>\r\n";
    let symbols = vec![
        Symbol::new(SymbolName::new("MIME_HTML_ONLY").unwrap()),
        Symbol::new(SymbolName::new("PROB_SPAM_HIGH").unwrap()),
    ];
    let doc = document(
        &Message::new(html.as_bytes()),
        &Envelope::default(),
        &symbols,
    );
    assert_eq!(doc.subject, "Big sale");
    assert!(doc.body.contains("Save") && doc.body.contains("today") && !doc.body.contains('<'));
    assert_eq!(doc.domains, ["example.net"]);
    assert_eq!(doc.sender_domain, "shop.example.net");
    assert!(doc.headers.contains(&"Subject".to_string()));
    assert_eq!(
        doc.symbols,
        ["MIME_HTML_ONLY"],
        "classifier symbols are not features"
    );
}

#[test]
fn snapshots_survive_bytes() {
    let check = trained(1);
    let bytes = check.snapshot().to_bytes();
    let reloaded = ClassifierCheck::new(Model::from_bytes(&bytes).unwrap(), config(1));
    assert_eq!(reloaded.snapshot(), check.snapshot());
}

#[tokio::test]
async fn passes_conformance() {
    let check = ClassifierCheck::new(
        trained(1).snapshot(),
        ClassifierConfig {
            auto_learn: false,
            ..config(1)
        },
    );
    conformance(
        &check,
        &[
            fixture(raw(5, true)),
            fixture(raw(6, false)),
            Fixture::message(""),
        ],
    )
    .await;
}
