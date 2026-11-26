use std::time::{Duration, Instant};

use mail_auth::{
    ResolverCache, TxtRecord,
    crypto::Ed25519Key,
    dkim::{DkimSigner, DomainKey},
    dmarc::DmarcRecord,
    dns::{ToFqdn, TxtRecordParser},
    headers::HeaderWriter,
    spf::SpfRecord,
};
use pellet_check::testing::{Fixture, conformance};
use pellet_core::Message;

use super::*;

const SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const PUBLIC: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const PUBLIC_B64: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

const MESSAGE: &str = "From: Ana Lindqvist <ana@example.com>\r\n\
    To: bo@example.org\r\n\
    Subject: Notes from Tuesday\r\n\
    Date: Tue, 3 Mar 2026 09:15:00 +0100\r\n\
    Message-ID: <notes-1@example.com>\r\n\
    \r\n\
    Attached are the notes from Tuesday.\r\n";

fn check() -> AuthCheck {
    AuthCheck::new(&AuthConfig {
        nameservers: vec!["192.0.2.53".parse().unwrap()],
        hostname: "mx.example.org".into(),
        ..AuthConfig::default()
    })
    .unwrap()
}

fn later() -> Instant {
    Instant::now() + Duration::from_secs(3600)
}

fn txt(check: &AuthCheck, name: &str, record: impl Into<TxtRecord>) {
    check.cache.txt.insert(
        name.to_fqdn().into_owned().into_boxed_str(),
        record.into(),
        later(),
    );
}

fn spf(check: &AuthCheck, domain: &str, record: &str) {
    txt(check, domain, SpfRecord::parse(record.as_bytes()));
}

fn dmarc(check: &AuthCheck, domain: &str, record: &str) {
    txt(
        check,
        &format!("_dmarc.{domain}"),
        DmarcRecord::parse(record.as_bytes()),
    );
}

fn dkim_key(check: &AuthCheck) {
    let record = format!("v=DKIM1; k=ed25519; p={PUBLIC_B64}");
    txt(
        check,
        "pellet._domainkey.example.com",
        DomainKey::parse(record.as_bytes()),
    );
}

fn signed(message: &str) -> String {
    let key = Ed25519Key::from_seed_and_public_key(&SEED, &PUBLIC).unwrap();
    let signature = DkimSigner::from_key(key)
        .domain("example.com")
        .selector("pellet")
        .headers(["From", "To", "Subject", "Date", "Message-ID"])
        .sign(message.as_bytes())
        .unwrap();
    format!("{}{message}", signature.to_header())
}

fn fixture(raw: &str, ip: &str, mail_from: &str) -> Fixture {
    let mut fixture = Fixture {
        message: Some(Message::new(raw.as_bytes())),
        ..Fixture::default()
    };
    fixture.envelope.client_ip = Some(ip.parse().unwrap());
    fixture.envelope.helo = Some("mail.example.com".into());
    fixture.envelope.mail_from = Some(mail_from.into());
    fixture
}

async fn run(check: &AuthCheck, fixture: &Fixture) -> Vec<Symbol> {
    check.run(&fixture.context(Stage::Data)).await.unwrap()
}

async fn names(check: &AuthCheck, fixture: &Fixture) -> Vec<String> {
    let mut names: Vec<String> = run(check, fixture)
        .await
        .into_iter()
        .map(|s| s.name.to_string())
        .collect();
    names.sort();
    names
}

fn option<'a>(symbols: &'a [Symbol], name: &str) -> &'a [String] {
    &symbols
        .iter()
        .find(|s| s.name.as_str() == name)
        .unwrap_or_else(|| panic!("{name} missing from {symbols:?}"))
        .options
}

#[tokio::test]
async fn spf_results() {
    let check = check();
    spf(&check, "example.com", "v=spf1 ip4:192.0.2.0/24 -all");
    spf(&check, "example.net", "v=spf1 ip4:192.0.2.0/24 ~all");
    spf(&check, "example.info", "v=spf1 ?all");

    let pass = run(&check, &fixture(MESSAGE, "192.0.2.25", "ana@example.com")).await;
    assert_eq!(option(&pass, "SPF_ALLOW"), ["example.com"]);

    for (ip, sender, expected) in [
        ("203.0.113.9", "ana@example.com", "SPF_FAIL"),
        ("203.0.113.9", "ana@example.net", "SPF_SOFTFAIL"),
        ("203.0.113.9", "ana@example.info", "SPF_NEUTRAL"),
        ("203.0.113.9", "ana@example.biz", "SPF_NA"),
    ] {
        let names = names(&check, &fixture(MESSAGE, ip, sender)).await;
        assert!(names.contains(&expected.to_string()), "{sender}: {names:?}");
    }
}

#[tokio::test]
async fn spf_errors() {
    let check = check();
    spf(
        &check,
        "broken.example.com",
        "v=spf1 ip4:not-an-address -all",
    );
    let perm = names(
        &check,
        &fixture(MESSAGE, "192.0.2.25", "a@broken.example.com"),
    )
    .await;
    assert!(perm.contains(&"SPF_PERMFAIL".to_string()), "{perm:?}");
    let temp = names(
        &check,
        &fixture(MESSAGE, "192.0.2.25", "a@_dns_error.example.com"),
    )
    .await;
    assert!(temp.contains(&"SPF_DNSFAIL".to_string()), "{temp:?}");
}

#[tokio::test]
async fn null_sender_checks_the_helo_name() {
    let check = check();
    spf(&check, "mail.example.com", "v=spf1 ip4:192.0.2.25 -all");
    let symbols = run(&check, &fixture(MESSAGE, "192.0.2.25", "")).await;
    assert_eq!(option(&symbols, "SPF_ALLOW"), ["mail.example.com"]);
}

#[tokio::test]
async fn signed_and_aligned_message_passes_dkim_and_dmarc() {
    let check = check();
    dkim_key(&check);
    dmarc(&check, "example.com", "v=DMARC1; p=reject");
    let symbols = run(
        &check,
        &fixture(&signed(MESSAGE), "203.0.113.9", "bounce@example.net"),
    )
    .await;
    assert_eq!(option(&symbols, "DKIM_SIGNED"), ["example.com"]);
    assert_eq!(option(&symbols, "DKIM_ALLOW"), ["example.com"]);
    assert_eq!(option(&symbols, "DMARC_POLICY_ALLOW"), ["example.com"]);
    assert!(!symbols.iter().any(|s| s.name.as_str() == "DKIM_REJECT"));
}

#[tokio::test]
async fn tampered_body_fails_dkim_and_dmarc_follows_the_policy() {
    for (policy, expected) in [
        ("reject", "DMARC_POLICY_REJECT"),
        ("quarantine", "DMARC_POLICY_QUARANTINE"),
        ("none", "DMARC_POLICY_SOFTFAIL"),
    ] {
        let check = check();
        dkim_key(&check);
        spf(&check, "example.com", "v=spf1 ip4:192.0.2.0/24 -all");
        dmarc(&check, "example.com", &format!("v=DMARC1; p={policy}"));
        let tampered = signed(MESSAGE).replace("notes from Tuesday.", "invoice attached.");
        let names = names(
            &check,
            &fixture(&tampered, "203.0.113.9", "ana@example.com"),
        )
        .await;
        assert!(names.contains(&"DKIM_REJECT".to_string()), "{names:?}");
        assert!(names.contains(&"SPF_FAIL".to_string()), "{names:?}");
        assert!(names.contains(&expected.to_string()), "{policy}: {names:?}");
    }
}

#[tokio::test]
async fn missing_key_is_a_permanent_dkim_failure() {
    let check = check();
    let names = names(
        &check,
        &fixture(&signed(MESSAGE), "192.0.2.25", "ana@example.com"),
    )
    .await;
    assert!(names.contains(&"DKIM_PERMFAIL".to_string()), "{names:?}");
    assert!(names.contains(&"DKIM_SIGNED".to_string()));
    assert!(!names.contains(&"DKIM_ALLOW".to_string()));
}

#[tokio::test]
async fn nothing_to_check_is_auth_na() {
    let check = check();
    let names = names(&check, &fixture(MESSAGE, "192.0.2.25", "ana@example.com")).await;
    assert_eq!(
        names,
        ["ARC_NA", "AUTH_NA", "DKIM_NA", "DMARC_NA", "SPF_NA"]
    );
}

#[tokio::test]
async fn without_a_client_address_spf_is_skipped() {
    let check = check();
    let mut no_ip = fixture(MESSAGE, "192.0.2.25", "ana@example.com");
    no_ip.envelope.client_ip = None;
    let names = names(&check, &no_ip).await;
    assert!(!names.iter().any(|n| n.starts_with("SPF_")), "{names:?}");
    assert!(names.contains(&"AUTH_NA".to_string()));
}

#[tokio::test]
async fn authenticated_clients_are_skipped() {
    let check = check();
    let mut submission = fixture(MESSAGE, "192.0.2.25", "ana@example.com");
    submission.envelope.authenticated = true;
    assert!(run(&check, &submission).await.is_empty());
}

#[test]
fn mail_from_domain_falls_back_to_helo() {
    let mut envelope = Envelope {
        mail_from: Some("ana@example.com".into()),
        helo: Some("mail.example.net".into()),
        ..Envelope::default()
    };
    assert_eq!(mail_from_domain(&envelope), "example.com");
    envelope.mail_from = Some(String::new());
    assert_eq!(mail_from_domain(&envelope), "mail.example.net");
}

#[tokio::test]
async fn passes_conformance() {
    let check = check();
    dkim_key(&check);
    spf(&check, "example.com", "v=spf1 ip4:192.0.2.0/24 -all");
    dmarc(&check, "example.com", "v=DMARC1; p=quarantine");
    conformance(
        &check,
        &[
            fixture(&signed(MESSAGE), "192.0.2.25", "ana@example.com"),
            fixture(MESSAGE, "203.0.113.9", "ana@example.com"),
            fixture("not a message", "203.0.113.9", ""),
            Fixture::default(),
        ],
    )
    .await;
}

#[tokio::test]
async fn add_txt_record_tells_record_kinds_apart() {
    let check = check();
    check.add_txt_record("example.com", "v=spf1 ip4:192.0.2.0/24 -all");
    check.add_txt_record("_dmarc.example.com", "v=DMARC1; p=reject");
    check.add_txt_record(
        "pellet._domainkey.example.com",
        &format!("v=DKIM1; k=ed25519; p={PUBLIC_B64}"),
    );
    let symbols = run(
        &check,
        &fixture(&signed(MESSAGE), "192.0.2.25", "ana@example.com"),
    )
    .await;
    assert_eq!(option(&symbols, "SPF_ALLOW"), ["example.com"]);
    assert_eq!(option(&symbols, "DKIM_ALLOW"), ["example.com"]);
    assert_eq!(option(&symbols, "DMARC_POLICY_ALLOW"), ["example.com"]);
}
