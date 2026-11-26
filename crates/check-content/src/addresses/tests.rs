use pellet_check::testing::{Fixture, conformance};

use super::*;

fn fixture(headers: &str) -> Fixture {
    let mut fixture = Fixture::message(&format!("{headers}Subject: Lunch\r\n\r\nbody\r\n"));
    fixture.envelope.mail_from = Some("ana@example.com".into());
    fixture.envelope.recipients = vec!["bo@example.org".into()];
    fixture
}

async fn names(fixture: &Fixture) -> Vec<String> {
    let mut names: Vec<String> = AddressCheck::new()
        .run(&fixture.context(Stage::Data))
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.name.to_string())
        .collect();
    names.sort();
    names
}

async fn relay_names(fixture: Fixture) -> Vec<String> {
    AddressCheck::new()
        .alias_domains(["relay.example.net"])
        .run(&fixture.context(Stage::Data))
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.name.to_string())
        .collect()
}

async fn of(headers: &str) -> Vec<String> {
    names(&fixture(headers)).await
}

fn has(names: &[String], name: &str) -> bool {
    names.iter().any(|n| n == name)
}

#[tokio::test]
async fn ordinary_message() {
    assert_eq!(
        of("From: Ana <ana@example.com>\r\nTo: Bo <bo@example.org>\r\n").await,
        [
            "FROM_EQ_ENV_FROM",
            "FROM_HAS_DN",
            "RCPT_COUNT_ONE",
            "TO_DN_ALL",
            "TO_MATCH_ENVRCPT_ALL"
        ]
    );
}

#[tokio::test]
async fn from_shapes() {
    let n = of("From: ana@example.com\r\nTo: bo@example.org\r\n").await;
    assert!(has(&n, "FROM_NO_DN") && has(&n, "TO_DN_NONE"));
    let n = of("From: \"ana@example.com\" <ana@example.com>\r\nTo: bo@example.org\r\n").await;
    assert!(has(&n, "FROM_DN_EQ_ADDR"));
    let n = of("From: \"support@bank.example\" <x@example.net>\r\nTo: bo@example.org\r\n").await;
    assert!(
        has(&n, "SPOOF_DISPLAY_NAME") && has(&n, "FROM_NEQ_ENV_FROM") && has(&n, "FORGED_SENDER"),
        "{n:?}"
    );
    let n = of("From: \"help@example.com\" <ana@example.com>\r\nTo: bo@example.org\r\n").await;
    assert!(
        has(&n, "FROM_NEQ_DISPLAY_NAME") && !has(&n, "SPOOF_DISPLAY_NAME"),
        "{n:?}"
    );
    let n = of("From: Ana<ana@example.com>\r\nTo: bo@example.org\r\n").await;
    assert!(has(&n, "NO_SPACE_IN_FROM"));
    let n = of("From: nobody\r\nTo: bo@example.org\r\n").await;
    assert!(has(&n, "FROM_INVALID"));
    let n = of("From: MAILER-DAEMON@example.net\r\nTo: bo@example.org\r\n").await;
    assert!(has(&n, "FROM_BOUNCE"));
}

#[tokio::test]
async fn envelope_sender() {
    let mut f = fixture("From: ana@example.com\r\nTo: bo@example.org\r\n");
    f.envelope.mail_from = Some("not-an-address".into());
    assert!(has(&names(&f).await, "ENV_FROM_INVALID"));
    f.envelope.mail_from = Some(String::new());
    f.envelope.recipients.push("cy@example.org".into());
    let n = names(&f).await;
    assert!(has(&n, "RCPT_BOUNCEMOREONE"));
    assert!(!has(&n, "FROM_EQ_ENV_FROM") && !has(&n, "FROM_NEQ_ENV_FROM"));
}

#[tokio::test]
async fn reply_to_relations() {
    for (reply, expected) in [
        ("Ana <ana@example.com>", "REPLYTO_EQ_FROM"),
        ("Sales <ana@example.com>", "REPLYTO_ADDR_EQ_FROM"),
        ("billing@example.com", "REPLYTO_DOM_EQ_FROM_DOM"),
        ("Ana <ana@example.net>", "REPLYTO_DOM_NEQ_FROM_DOM"),
        ("bo@example.org", "REPLYTO_EQ_TO_ADDR"),
    ] {
        let n = of(&format!(
            "From: Ana <ana@example.com>\r\nTo: bo@example.org\r\nReply-To: {reply}\r\n"
        ))
        .await;
        assert!(
            has(&n, "HAS_REPLYTO") && has(&n, expected),
            "{reply}: {n:?}"
        );
    }
    let n = of(
        "From: Ana <ana@example.com>\r\nTo: bo@example.org\r\nReply-To: Ana <ana@example.net>\r\n",
    )
    .await;
    assert!(has(&n, "REPLYTO_DN_EQ_FROM_DN"));
    let n = of("From: ana@example.com\r\nTo: bo@example.org\r\nReply-To: garbage\r\n").await;
    assert!(has(&n, "REPLYTO_UNPARSABLE"));
    for list in [
        "List-Id: <plans.example.org>",
        "List-Post: <mailto:plans@example.org>",
        "Mailing-List: contact plans-help@example.org",
        "Precedence: list",
    ] {
        let n = of(&format!(
            "From: Ana <ana@example.com>\r\nTo: plans@example.org\r\nReply-To: plans@example.org\r\n{list}\r\n"
        ))
        .await;
        assert!(
            !has(&n, "REPLYTO_EQ_TO_ADDR"),
            "{list}: replies to a list go to the list"
        );
    }
}

#[tokio::test]
async fn to_relations() {
    let n = of("From: ana@example.com\r\nTo: ana@example.com\r\n").await;
    assert!(has(&n, "TO_EQ_FROM") && !has(&n, "TO_MATCH_ENVRCPT_SOME"));
    let n = of("From: ana@example.com\r\nTo: cy@example.com\r\n").await;
    assert!(has(&n, "TO_DOM_EQ_FROM_DOM"));
    let n = of("From: ana@example.com\r\nTo: Bo <bo@example.org>, cy@example.org\r\n").await;
    assert!(has(&n, "TO_DN_SOME") && has(&n, "RCPT_COUNT_TWO"));
    let n = of("From: ana@example.com\r\nTo: \"bo@example.org\" <bo@example.org>\r\n").await;
    assert!(has(&n, "TO_DN_EQ_ADDR_ALL"));
    let n = of("From: ana@example.com\r\nTo: < bo@example.org >\r\n").await;
    assert!(has(&n, "TO_WRAPPED_IN_SPACES"));
    let mut f = fixture("From: ana@example.com\r\nTo: bo@example.org\r\n");
    f.envelope.recipients.push("hidden@example.org".into());
    assert!(has(&names(&f).await, "TO_MATCH_ENVRCPT_SOME"));
}

#[tokio::test]
async fn recipient_counts_and_order() {
    let list: Vec<String> = (b'a'..=b'h')
        .map(|c| format!("{}@example.org", c as char))
        .collect();
    let n = of(&format!(
        "From: ana@example.com\r\nTo: {}\r\n",
        list.join(", ")
    ))
    .await;
    assert!(
        has(&n, "RCPT_COUNT_SEVEN") && has(&n, "SORTED_RECIPS"),
        "{n:?}"
    );
    assert_eq!(count_bucket(0), "RCPT_COUNT_ZERO");
    assert_eq!(count_bucket(4), "RCPT_COUNT_THREE");
    assert_eq!(count_bucket(6), "RCPT_COUNT_FIVE");
    assert_eq!(count_bucket(50), "RCPT_COUNT_TWELVE");
    assert_eq!(count_bucket(51), "RCPT_COUNT_GT_50");
    let n = of("From: ana@example.com\r\nTo: undisclosed-recipients:;\r\n").await;
    assert!(has(&n, "RCPT_COUNT_ZERO"));
}

#[tokio::test]
async fn recipient_named_in_subject() {
    let raw = |subject: &str| {
        let mut f = Fixture::message(&format!(
            "From: ana@example.com\r\nTo: bo@example.org\r\nSubject: {subject}\r\n\r\nb"
        ));
        f.envelope.recipients = vec!["bobby@example.org".into()];
        f
    };
    assert!(has(
        &names(&raw("Invoice for bobby@example.org")).await,
        "RCPT_IN_SUBJECT"
    ));
    assert!(has(
        &names(&raw("Your EXAMPLE.ORG account")).await,
        "RCPT_DOMAIN_IN_SUBJECT"
    ));
    assert!(has(
        &names(&raw("Hi bobby, news")).await,
        "RCPT_LOCAL_IN_SUBJECT"
    ));
    assert!(!has(&names(&raw("Lunch")).await, "RCPT_LOCAL_IN_SUBJECT"));
}

#[tokio::test]
async fn passes_conformance() {
    conformance(
        &AddressCheck::new(),
        &[
            fixture("From: Ana <ana@example.com>\r\nTo: Bo <bo@example.org>\r\nReply-To: x@example.net\r\n"),
            fixture("From: nobody\r\n"),
            Fixture::message(""),
        ],
    )
    .await;
}

#[tokio::test]
async fn forged_recipients_and_receipts() {
    let mut f = fixture("From: ana@example.com\r\nTo: someone@example.net\r\n");
    assert!(has(&names(&f).await, "FORGED_RECIPIENTS"));
    f.envelope.authenticated = true;
    assert!(!has(&names(&f).await, "FORGED_RECIPIENTS"));
    for to in ["x7k2@relay.example.net", "x7k2@eu.relay.example.net"] {
        let n = relay_names(fixture(&format!("From: ana@example.com\r\nTo: {to}\r\n"))).await;
        assert!(!has(&n, "FORGED_RECIPIENTS"), "{to}: {n:?}");
    }
    let n = relay_names(fixture(
        "From: ana@example.com\r\nTo: x7k2@notrelay.example.net\r\n",
    ))
    .await;
    assert!(has(&n, "FORGED_RECIPIENTS"), "{n:?}");
    let n = of("From: ana@example.com\r\nTo: bo@example.org\r\nDisposition-Notification-To: track@example.net\r\nX-Confirm-Reading-To: <track@example.net>\r\n").await;
    assert!(
        has(&n, "HEADER_FORGED_MDN") && has(&n, "HEADER_RCONFIRM_MISMATCH"),
        "{n:?}"
    );
    let n = of("From: ana@example.com\r\nTo: bo@example.org\r\nDisposition-Notification-To: ana@example.com\r\n").await;
    assert!(!has(&n, "HEADER_FORGED_MDN"));
}
