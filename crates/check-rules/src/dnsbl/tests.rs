use pellet_check::testing::{Fixture, conformance};
use pellet_dns::{DnsError, testing::FakeResolver};

use super::*;

const MESSAGE: &str = "Received: from relay (relay.example.net [198.51.100.20]) by mx.example.org with ESMTPS\r\n\
    From: Ana <ana@example.com>\r\n\
    To: bo@example.org\r\n\
    Subject: Notes\r\n\
    MIME-Version: 1.0\r\n\
    Content-Type: text/html; charset=utf-8\r\n\
    \r\n\
    <p>Read <a href=\"https://www.shop.example.info/deal\">the offer</a> today.</p>\r\n";

fn fixture() -> Fixture {
    let mut fixture = Fixture::message(MESSAGE);
    fixture.envelope.client_ip = Some("192.0.2.25".parse().unwrap());
    fixture.envelope.mail_from = Some("ana@example.com".into());
    fixture
}

fn check(resolver: FakeResolver) -> DnsListCheck {
    DnsListCheck::new(Arc::new(RuleSet::bundled().unwrap()), Arc::new(resolver))
}

async fn run(check: &DnsListCheck, fixture: &Fixture) -> Vec<Symbol> {
    check.run(&fixture.context(Stage::Data)).await.unwrap()
}

fn option<'a>(symbols: &'a [Symbol], name: &str) -> Option<&'a [String]> {
    symbols
        .iter()
        .find(|s| s.name.as_str() == name)
        .map(|s| s.options.as_slice())
}

#[tokio::test]
async fn client_and_received_addresses() {
    let resolver = FakeResolver::new()
        .with_ipv4("25.2.0.192.zen.spamhaus.org", &["127.0.0.2"])
        .with_ipv4("20.100.51.198.zen.spamhaus.org", &["127.0.0.4"]);
    let symbols = run(&check(resolver), &fixture()).await;
    assert_eq!(
        option(&symbols, "RBL_SPAMHAUS_SBL"),
        Some(&["192.0.2.25".to_string()][..])
    );
    assert_eq!(
        option(&symbols, "RECEIVED_SPAMHAUS_XBL"),
        Some(&["198.51.100.20".to_string()][..])
    );
    assert!(
        option(&symbols, "RBL_SPAMHAUS_XBL").is_none(),
        "location decides the symbol"
    );
}

#[tokio::test]
async fn domains_from_links_and_senders() {
    let resolver = FakeResolver::new()
        .with_ipv4("example.info.dbl.spamhaus.org", &["127.0.1.4"])
        .with_ipv4("example.com.multi.surbl.org", &["127.0.0.8"]);
    let symbols = run(&check(resolver), &fixture()).await;
    assert_eq!(
        option(&symbols, "DBL_PHISH"),
        Some(&["example.info".to_string()][..]),
        "{symbols:?}"
    );
    assert!(option(&symbols, "PH_SURBL_MULTI").is_some(), "{symbols:?}");
}

#[tokio::test]
async fn dkim_pass_domains_only_for_whitelists() {
    let resolver = FakeResolver::new().with_ipv4("example.com.dwl.dnswl.org", &["127.0.9.2"]);
    let plain = run(
        &check(FakeResolver::new().with_ipv4("example.com.dwl.dnswl.org", &["127.0.9.2"])),
        &fixture(),
    )
    .await;
    assert!(
        plain.iter().all(|s| !s.name.as_str().starts_with("DWL_")),
        "{plain:?}"
    );
    let mut signed = fixture();
    signed.earlier =
        vec![Symbol::new(SymbolName::new("DKIM_ALLOW").unwrap()).with_option("example.com")];
    let symbols = run(&check(resolver), &signed).await;
    assert!(
        symbols
            .iter()
            .any(|s| s.name.as_str().starts_with("DWL_DNSWL")),
        "{symbols:?}"
    );
}

#[tokio::test]
async fn hashed_email_lists() {
    let name = format!(
        "{}.ebl.msbl.org",
        pellet_rules::Expr::parse("hash('ana@example.com', 'sha1')")
            .unwrap()
            .eval(&NoEnv)
            .as_str()
            .unwrap()
    );
    let resolver = FakeResolver::new().with_ipv4(&name, &["127.0.0.2"]);
    let symbols = run(&check(resolver), &fixture()).await;
    assert!(
        symbols
            .iter()
            .any(|s| s.name.as_str().starts_with("MSBL_EBL")),
        "{symbols:?}"
    );
}

struct NoEnv;

impl pellet_rules::Env for NoEnv {
    fn var(&self, _: &str) -> Value {
        Value::Null
    }
    fn symbol(&self, _: &str) -> bool {
        false
    }
    fn list_contains(&self, _: &str, _: &str) -> bool {
        false
    }
}

#[tokio::test]
async fn failures_and_local_addresses_are_quiet() {
    let resolver =
        Arc::new(FakeResolver::new().with_error("25.2.0.192.zen.spamhaus.org", DnsError::Timeout));
    let check = DnsListCheck::new(Arc::new(RuleSet::bundled().unwrap()), resolver.clone());
    assert!(run(&check, &fixture()).await.is_empty());
    let mut local = Fixture::message("From: a@example.com\r\n\r\nno links\r\n");
    local.envelope.client_ip = Some("10.0.0.3".parse().unwrap());
    let before = resolver.queries();
    run(&check, &local).await;
    assert!(
        resolver.queries() - before < 10,
        "a private client is not looked up"
    );
    let mut authenticated = fixture();
    authenticated.envelope.authenticated = true;
    assert!(run(&check, &authenticated).await.is_empty());
}

#[tokio::test]
async fn queries_are_bounded_and_deduplicated() {
    let links: String = (0..100)
        .map(|i| format!("<a href=\"https://h{i}.example{i}.net/\">x</a>"))
        .collect();
    let mut fixture = Fixture::message(&format!(
        "From: a@example.com\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{links}\r\n"
    ));
    fixture.envelope.client_ip = Some("192.0.2.25".parse().unwrap());
    let resolver = Arc::new(FakeResolver::new());
    let check = DnsListCheck::new(Arc::new(RuleSet::bundled().unwrap()), resolver.clone());
    run(&check, &fixture).await;
    assert!(resolver.queries() <= MAX_QUERIES, "{}", resolver.queries());
}

#[test]
fn received_addresses() {
    let message = Message::new(
        &b"Received: from a ([192.0.2.1]) by b\r\nReceived: from c ([IPv6:2001:db8::5]) by d ([192.0.2.1])\r\n\r\n"[..],
    );
    let ips = received_ips(&message);
    assert_eq!(
        ips,
        [
            "192.0.2.1".parse::<IpAddr>().unwrap(),
            "2001:db8::5".parse().unwrap()
        ]
    );
}

#[tokio::test]
async fn passes_conformance() {
    let resolver = FakeResolver::new()
        .with_ipv4("25.2.0.192.zen.spamhaus.org", &["127.0.0.2", "127.0.0.10"])
        .with_ipv4("example.info.dbl.spamhaus.org", &["127.0.1.2"]);
    conformance(&check(resolver), &[fixture(), Fixture::message("")]).await;
}
