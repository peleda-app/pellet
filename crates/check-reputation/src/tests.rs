use pellet_check::testing::{Fixture, conformance};
use pellet_state_memory::MemoryState;

use super::*;

fn check() -> (ReputationCheck, Arc<MemoryState>) {
    let state = Arc::new(MemoryState::new(1000));
    (
        ReputationCheck::new(state.clone(), ReputationConfig::default()),
        state,
    )
}

fn symbol(name: &str, option: Option<&str>) -> Symbol {
    let symbol = Symbol::new(SymbolName::new(name).unwrap());
    match option {
        Some(o) => symbol.with_option(o),
        None => symbol,
    }
}

fn fixture(ip: &str, symbols: Vec<Symbol>) -> Fixture {
    let mut fixture = Fixture::message("From: ana@example.com\r\n\r\nb");
    fixture.envelope.client_ip = Some(ip.parse().unwrap());
    fixture.earlier = symbols;
    fixture
}

fn spammy(ip: &str) -> Fixture {
    fixture(
        ip,
        vec![symbol("RBL_SPAMHAUS_SBL", None), symbol("SPF_FAIL", None)],
    )
}

fn clean(ip: &str) -> Fixture {
    fixture(
        ip,
        vec![
            symbol("DKIM_ALLOW", Some("example.com")),
            symbol("SPF_ALLOW", Some("example.com")),
            symbol("DMARC_POLICY_ALLOW", Some("example.com")),
        ],
    )
}

async fn run(check: &ReputationCheck, fixture: &Fixture) -> Vec<Symbol> {
    check.run(&fixture.context(Stage::Data)).await.unwrap()
}

#[tokio::test]
async fn spammy_addresses_build_a_reputation() {
    let (check, _) = check();
    for _ in 0..4 {
        assert!(
            run(&check, &spammy("192.0.2.7")).await.is_empty(),
            "not enough samples yet"
        );
    }
    let out = run(&check, &spammy("192.0.2.7")).await;
    assert!(out.is_empty(), "the fifth sample is counted after judging");
    let out = run(&check, &spammy("192.0.2.7")).await;
    assert_eq!(out[0].name.as_str(), "REPUTATION_IP_SPAM");
    assert_eq!(out[0].options, ["5/5"]);
    assert!(
        run(&check, &spammy("198.51.100.1")).await.is_empty(),
        "other addresses are separate"
    );
}

#[tokio::test]
async fn authenticated_domains_build_a_reputation() {
    let (check, _) = check();
    for _ in 0..5 {
        run(&check, &clean("192.0.2.8")).await;
    }
    let names: Vec<String> = run(&check, &clean("203.0.113.5"))
        .await
        .into_iter()
        .map(|s| s.name.to_string())
        .collect();
    assert_eq!(
        names,
        ["REPUTATION_DOMAIN_HAM"],
        "a new address, a known domain"
    );
}

#[tokio::test]
async fn mixed_records_and_weak_signals_stay_silent() {
    let (check, _) = check();
    for i in 0..10 {
        let f = if i % 2 == 0 {
            spammy("192.0.2.9")
        } else {
            clean("192.0.2.9")
        };
        run(&check, &f).await;
    }
    assert!(
        run(&check, &fixture("192.0.2.9", vec![])).await.is_empty(),
        "half and half"
    );
    let key = ip_key("192.0.2.9".parse().unwrap()).unwrap();
    assert_eq!(check.counts(&key).await, Counts { ham: 5, spam: 5 });
    run(
        &check,
        &fixture("192.0.2.9", vec![symbol("RBL_SPAMHAUS_SBL", None)]),
    )
    .await;
    assert_eq!(
        check.counts(&key).await.total(),
        10,
        "a blocklist hit alone teaches nothing"
    );
}

#[tokio::test]
async fn ipv6_counts_by_prefix_and_local_addresses_are_ignored() {
    assert_eq!(
        ip_key("2001:db8:1:2:aaaa::1".parse().unwrap()),
        ip_key("2001:db8:1:2:bbbb::9".parse().unwrap())
    );
    assert_ne!(
        ip_key("2001:db8:1:2::1".parse().unwrap()),
        ip_key("2001:db8:1:3::1".parse().unwrap())
    );
    assert_eq!(
        ip_key("::ffff:192.0.2.1".parse().unwrap()),
        ip_key("192.0.2.1".parse().unwrap())
    );
    assert!(ip_key("10.0.0.1".parse().unwrap()).is_none());
}

#[tokio::test]
async fn feedback_and_authenticated_clients() {
    let (check, state) = check();
    let envelope = Envelope {
        client_ip: Some("192.0.2.10".parse().unwrap()),
        ..Envelope::default()
    };
    for _ in 0..5 {
        check.learn(&envelope, &[], true).await;
    }
    let key = ip_key("192.0.2.10".parse().unwrap()).unwrap();
    assert_eq!(check.counts(&key).await.spam, 5);
    let mut submission = spammy("192.0.2.10");
    submission.envelope.authenticated = true;
    run(&check, &submission).await;
    assert_eq!(
        check.counts(&key).await.spam,
        5,
        "own users are not counted"
    );
    assert!(!state.is_empty());
}

#[test]
fn counts_encoding() {
    let counts = Counts {
        ham: 3,
        spam: 70000,
    };
    assert_eq!(Counts::decode(&counts.encode()), counts);
    assert_eq!(Counts::decode(b"short"), Counts::default());
}

#[tokio::test]
async fn passes_conformance() {
    let (check, _) = check();
    conformance(
        &check,
        &[fixture("192.0.2.11", vec![]), Fixture::message("")],
    )
    .await;
}

#[tokio::test]
async fn spam_traps_count_as_spam() {
    let (check, _) = check();
    let trapped = fixture("192.0.2.9", vec![symbol("SPAM_TRAP", None)]);
    for _ in 0..5 {
        run(&check, &trapped).await;
    }
    let names: Vec<String> = run(&check, &trapped)
        .await
        .into_iter()
        .map(|s| s.name.to_string())
        .collect();
    assert_eq!(names, ["REPUTATION_IP_SPAM"]);
}
