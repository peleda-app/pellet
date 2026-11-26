use pellet_check::testing::{Fixture, conformance};
use pellet_core::Message;

use super::*;

const MESSAGE: &str = "From: \"Dr. Ana Lindqvist\" <ana@example.com>\r\n\
    To: bo+news@example.org\r\n\
    Subject: Act now!\r\n\
    Date: Tue, 3 Mar 2026 09:15:00 +0100\r\n\
    Message-ID: <a1@example.com>\r\n\
    \r\n\
    Limited offer for SEO services.\r\n";

fn bundled() -> RulesCheck {
    RulesCheck::new(Arc::new(RuleSet::bundled().unwrap()))
}

fn custom(text: &str) -> RulesCheck {
    let mut set = RuleSet::default();
    set.add_rules("test.toml", text).unwrap();
    RulesCheck::new(Arc::new(set))
}

fn fixture(raw: &str) -> Fixture {
    let mut fixture = Fixture {
        message: Some(Message::new(raw.as_bytes())),
        ..Fixture::default()
    };
    fixture.envelope.mail_from = Some("ana@example.com".into());
    fixture.envelope.recipients = vec!["bo+news@example.org".into()];
    fixture
}

fn with_earlier(mut fixture: Fixture, names: &[&str]) -> Fixture {
    fixture.earlier = names
        .iter()
        .map(|n| Symbol::new(SymbolName::new(n).unwrap()))
        .collect();
    fixture
}

async fn names(check: &RulesCheck, fixture: &Fixture) -> Vec<String> {
    check
        .run(&fixture.context(Stage::Data))
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.name.to_string())
        .collect()
}

fn has(names: &[String], name: &str) -> bool {
    names.iter().any(|n| n == name)
}

#[tokio::test]
async fn bundled_rules_fire_on_message_fields() {
    let names = names(&bundled(), &fixture(MESSAGE)).await;
    for expected in [
        "SUBJECT_ENDS_EXCLAIM",
        "FROM_NAME_HAS_TITLE",
        "TAGGED_RCPT",
        "HAS_SEO_WORD",
    ] {
        assert!(has(&names, expected), "{expected} missing from {names:?}");
    }
    assert!(
        !has(&names, "SUBJECT_ENDS_QUESTION"),
        "first matching clause only"
    );
    assert!(!has(&names, "FAKE_REPLY"));
}

#[tokio::test]
async fn composites_see_symbols_from_other_checks() {
    let check = bundled();
    let plain = names(&check, &fixture(MESSAGE)).await;
    assert!(!has(&plain, "DMARC_POLICY_ALLOW_WITH_FAILURES"));
    let failing = with_earlier(fixture(MESSAGE), &["DMARC_POLICY_ALLOW", "SPF_FAIL"]);
    assert!(has(
        &names(&check, &failing).await,
        "DMARC_POLICY_ALLOW_WITH_FAILURES"
    ));
}

#[tokio::test]
async fn later_rules_see_earlier_rules() {
    let check = custom(
        "[rule.B]\nscope = \"any\"\npriority = 2\ncondition = [ { if = \"$FIRST\", then = \"'SECOND'\" } ]\n\
         [rule.A]\nscope = \"any\"\npriority = 1\ncondition = \"'FIRST'\"\n\
         [rule.C]\nscope = \"any\"\npriority = 0\ncondition = [ { if = \"$SECOND\", then = \"'NEVER'\" } ]\n",
    );
    assert_eq!(names(&check, &fixture(MESSAGE)).await, ["FIRST", "SECOND"]);
}

#[tokio::test]
async fn header_rules_run_per_field() {
    let check = custom(
        "[rule.H]\nscope = \"header\"\ncondition = [ { if = \"name_lower == 'x-php-script' && contains(value_lower, 'eval()')\", then = \"'X_PHP_EVAL'\" } ]\n",
    );
    let raw = MESSAGE.replace(
        "Subject:",
        "X-PHP-Script: index.php EVAL() call\r\nSubject:",
    );
    assert_eq!(names(&check, &fixture(&raw)).await, ["X_PHP_EVAL"]);
    assert!(names(&check, &fixture(MESSAGE)).await.is_empty());
}

#[tokio::test]
async fn email_rules_know_locations() {
    let check = custom(
        "[rule.E]\nscope = \"email\"\ncondition = [ { if = \"location == 'env_to' && local == 'bo+news' && sld == 'example.org'\", then = \"'ENV_TO_SEEN'\" } ]\n\
         [rule.F]\nscope = \"email\"\ncondition = [ { if = \"location == 'from' && name == 'Dr. Ana Lindqvist'\", then = \"'FROM_SEEN'\" } ]\n",
    );
    assert_eq!(
        names(&check, &fixture(MESSAGE)).await,
        ["ENV_TO_SEEN", "FROM_SEEN"]
    );
}

#[tokio::test]
async fn lists_and_computed_names() {
    let mut set = RuleSet::bundled().unwrap();
    set.lists_mut()
        .insert_text("stwt_free_domains", "example.com\n");
    let check = RulesCheck::new(Arc::new(set));
    let names = names(&check, &fixture(MESSAGE)).await;
    assert!(has(&names, "FREEMAIL_FROM"), "{names:?}");
    assert!(has(&names, "FREEMAIL_ENV_FROM"), "{names:?}");

    let trusted = with_earlier(
        fixture(&MESSAGE.replace("ana@example.com", "ana@126.com")),
        &["DMARC_POLICY_ALLOW"],
    );
    assert!(has(&bundled_names(&trusted).await, "TRUSTED_DOMAIN"));
}

async fn bundled_names(fixture: &Fixture) -> Vec<String> {
    names(&bundled(), fixture).await
}

#[tokio::test]
async fn undeclared_results_are_ignored() {
    let check = custom("[rule.X]\nscope = \"any\"\ncondition = \"'lower' + 'case'\"\n");
    assert!(names(&check, &fixture(MESSAGE)).await.is_empty());
}

#[tokio::test]
async fn null_sender_has_no_env_from() {
    let check = custom(
        "[rule.N]\nscope = \"any\"\ncondition = [ { if = \"is_empty(env_from)\", then = \"'NULL_SENDER'\" } ]\n",
    );
    let mut bounce = fixture(MESSAGE);
    bounce.envelope.mail_from = Some(String::new());
    assert_eq!(names(&check, &bounce).await, ["NULL_SENDER"]);
    assert!(names(&check, &fixture(MESSAGE)).await.is_empty());
}

#[tokio::test]
async fn unparsable_messages_still_run() {
    let names = bundled_names(&fixture("garbage without headers")).await;
    assert!(!has(&names, "FROM_NAME_HAS_TITLE"));
}

#[test]
fn is_late_and_declares_rule_symbols() {
    let check = bundled();
    assert!(check.late());
    assert!(
        check
            .symbols()
            .iter()
            .any(|s| s.as_str() == "AUTH_NA_OR_FAIL")
    );
}

#[tokio::test]
async fn passes_conformance() {
    conformance(
        &bundled(),
        &[
            fixture(MESSAGE),
            with_earlier(
                fixture(MESSAGE),
                &[
                    "DMARC_POLICY_ALLOW",
                    "SPF_FAIL",
                    "DKIM_NA",
                    "SPF_NA",
                    "DMARC_NA",
                    "ARC_NA",
                ],
            ),
            fixture(""),
            Fixture::default(),
        ],
    )
    .await;
}

#[tokio::test]
async fn url_rules_run_per_link() {
    let raw = "From: a@example.com\r\nSubject: news\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<a href=\"https://blog.example.net/wp-content/plugins/x.php\">read</a> <a href=\"https://site.example.onion/\">hidden</a> <a href=\"https://www.google.example/url?q=x\">g</a>\r\n";
    let n = names(&bundled(), &fixture(raw)).await;
    for expected in ["WP_COMPROMISED", "HAS_ONION_URI"] {
        assert!(has(&n, expected), "{expected} missing from {n:?}");
    }
    let mut set = RuleSet::bundled().unwrap();
    set.lists_mut().insert_text(
        "stwt_openphish",
        "https://blog.example.net/wp-content/plugins/x.php\n",
    );
    let listed = names(&RulesCheck::new(Arc::new(set)), &fixture(raw)).await;
    assert!(has(&listed, "PHISHED_OPENPHISH"), "{listed:?}");
}
