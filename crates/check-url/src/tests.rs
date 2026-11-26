use pellet_check::testing::{Fixture, conformance};

use super::*;

fn check() -> UrlCheck {
    UrlCheck::new(["redirect.example.net", "t.example.org"]).click_trackers(["click.example.net"])
}

fn html(body: &str) -> Fixture {
    Fixture::message(&format!(
        "Subject: Notice\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Dear customer, please review the information about your account below.</p>{body}\r\n"
    ))
}

fn plain(body: &str) -> Fixture {
    Fixture::message(&format!(
        "Subject: Notice\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n"
    ))
}

async fn run(fixture: &Fixture) -> Vec<Symbol> {
    check().run(&fixture.context(Stage::Data)).await.unwrap()
}

async fn names(fixture: &Fixture) -> Vec<String> {
    let mut names: Vec<String> = run(fixture)
        .await
        .into_iter()
        .map(|s| s.name.to_string())
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn ordinary_links_are_clean() {
    assert!(
        names(&html(
            "<a href=\"https://www.example.com/help\">www.example.com</a>"
        ))
        .await
        .is_empty()
    );
    assert!(
        names(&plain(
            "See https://example.com/docs for the details of the change we made."
        ))
        .await
        .is_empty()
    );
}

#[tokio::test]
async fn phishing_anchor() {
    let symbols = run(&html(
        "<a href=\"https://login.example.net/\">https://bank.example.com</a>",
    ))
    .await;
    let phishing = symbols
        .iter()
        .find(|s| s.name.as_str() == "PHISHING")
        .unwrap();
    assert_eq!(phishing.options, ["example.com"]);
    assert!(
        names(&html(
            "<a href=\"https://login.example.net/\">bank.example.com</a>"
        ))
        .await
        .contains(&"PHISHING".to_string())
    );
    let unwrapped = "<a href=\"https://redirect.example.net/r?u=https%3A%2F%2Fevil.example.info%2F\">www.example.com</a>";
    let n = names(&html(unwrapped)).await;
    assert!(
        n.contains(&"PHISHING".to_string()) && n.contains(&"REDIRECTOR_URL".to_string()),
        "{n:?}"
    );
    let honest = "<a href=\"https://redirect.example.net/r?u=https%3A%2F%2Fwww.example.com%2F\">www.example.com</a>";
    assert!(!names(&html(honest)).await.contains(&"PHISHING".to_string()));
}

#[tokio::test]
async fn scheme_and_host_tricks() {
    assert_eq!(
        names(&html(
            "<a href=\"http://www.example.com/\">https://www.example.com/</a>"
        ))
        .await,
        ["HTTP_TO_HTTPS"]
    );
    assert_eq!(
        names(&html("<a href=\"http://192.0.2.7/login\">Log in</a>")).await,
        ["HTTP_TO_IP"]
    );
    assert_eq!(
        names(&html(
            "<a href=\"http://www.example.com@evil.example.net/\">Log in</a>"
        ))
        .await,
        ["SUSPICIOUS_URL"]
    );
    assert_eq!(
        names(&html("<a href=\"http://3221225985/\">Log in</a>")).await,
        ["HTTP_TO_IP", "SUSPICIOUS_URL"]
    );
    assert!(
        names(&html(
            "<a href=\"https://p\u{430}ypal.example/\">Log in</a>"
        ))
        .await
        .contains(&"HOMOGRAPH_URL".to_string())
    );
    assert!(
        names(&html(
            "<a href=\"https://\u{43f}\u{440}\u{438}.example.com/\">x</a>"
        ))
        .await
        .contains(&"MIXED_CHARSET_URL".to_string())
    );
    assert_eq!(
        names(&plain(
            "Go to https://exa\u{200b}mple.com/x now and confirm your details today."
        ))
        .await,
        ["ZERO_WIDTH_SPACE_URL"]
    );
    assert_eq!(
        names(&html("<a href=\"http://bad host.example/\">x</a>")).await,
        ["UNPARSABLE_URL"]
    );
}

#[tokio::test]
async fn redirectors() {
    let n = names(&html(
        "<a href=\"http://t.example.org/c?u=https%3A%2F%2Fredirect.example.net%2Fr\">Read</a>",
    ))
    .await;
    assert_eq!(
        n,
        [
            "REDIRECTOR_URL",
            "URL_REDIRECTOR_INSECURE",
            "URL_REDIRECTOR_NESTED"
        ]
    );
}

#[tokio::test]
async fn link_only_bodies_and_subject() {
    assert_eq!(
        names(&plain("https://offer.example.net/x")).await,
        ["URL_ONLY"]
    );
    let only = Fixture::message(
        "Subject: x\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<a href=\"https://offer.example.net/\">Click</a>\r\n",
    );
    assert_eq!(names(&only).await, ["BODY_URI_ONLY"]);
    let subject = Fixture::message(
        "Subject: see www.offer.example.net\r\n\r\nPlain words without any links in the body at all.\r\n",
    );
    assert_eq!(names(&subject).await, ["URL_IN_SUBJECT"]);
}

#[tokio::test]
async fn odd_link_count_in_alternatives() {
    let raw = "MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nRead the report about the quarter at https://example.com/c today.\r\n--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Read the report about the quarter at <a href=\"https://example.com/a\">the site</a> and <a href=\"https://example.com/b\">more</a> today.</p>\r\n--b--\r\n";
    assert!(
        names(&Fixture::message(raw))
            .await
            .contains(&"URI_COUNT_ODD".to_string())
    );
}

#[test]
fn shown_urls() {
    assert_eq!(
        shown_url("https://bank.example.com").unwrap().registrable(),
        "example.com"
    );
    assert_eq!(
        shown_url("bank.example.com").unwrap().host,
        "bank.example.com"
    );
    assert!(shown_url("Click here").is_none());
    assert!(shown_url("v2").is_none());
    for not_a_domain in [
        "yarn.lock",
        "package.json",
        "frontend/yarn.lock",
        "94.75",
        "9.0.5",
        "d.u.k.",
        "README.md",
        "build.sh",
        "user@example.com",
        "[user@example.com]",
    ] {
        assert!(shown_url(not_a_domain).is_none(), "{not_a_domain}");
    }
    for domain in ["www.example.md", "https://example.md", "shop.example.lt"] {
        assert!(shown_url(domain).is_some(), "{domain}");
    }
}

#[tokio::test]
async fn phishing_needs_a_shown_domain_and_a_known_destination() {
    for clean in [
        "<a href=\"https://code.example.net/blob/main/yarn.lock\">yarn.lock</a>",
        "<a href=\"https://shop.example.net/cart\">94.75</a>",
        "<a href=\"https://video.example.net/account\">[user@example.com]</a>",
        "<a href=\"https://t.example.org/c/abc123\">www.example.com</a>",
        "<a href=\"https://eu1.click.example.net/l/abc123\">www.example.com</a>",
    ] {
        assert!(
            !names(&html(clean)).await.contains(&"PHISHING".to_string()),
            "{clean}"
        );
    }
    assert!(
        names(&html(
            "<a href=\"https://t.example.org/c?u=https%3A%2F%2Fevil.example.info%2F\">www.example.com</a>"
        ))
        .await
        .contains(&"PHISHING".to_string()),
        "a redirector that shows its target is still followed"
    );
}

#[tokio::test]
async fn click_trackers_make_no_redirector_symbols() {
    assert!(
        names(&html(
            "<a href=\"http://click.example.net/l/abc123\">Read the news</a>"
        ))
        .await
        .is_empty()
    );
}

#[tokio::test]
async fn accented_latin_is_latin() {
    for clean in [
        "<a href=\"https://siunt\u{117}.example.lt/\">Track</a>",
        "<a href=\"https://\u{161}ok\u{16b}.example.com/\">Track</a>",
        "<a href=\"https://caf\u{e9}.example.fr/\">Menu</a>",
    ] {
        let n = names(&html(clean)).await;
        assert!(
            !n.contains(&"HOMOGRAPH_URL".to_string())
                && !n.contains(&"MIXED_CHARSET_URL".to_string()),
            "{clean}: {n:?}"
        );
    }
    assert!(
        names(&html(
            "<a href=\"https://\u{161}k\u{43e}la.example.lt/\">x</a>"
        ))
        .await
        .contains(&"HOMOGRAPH_URL".to_string()),
        "accented Latin next to Cyrillic is still a homograph"
    );
}

#[tokio::test]
async fn passes_conformance() {
    conformance(
        &check(),
        &[
            html("<a href=\"https://login.example.net/\">https://bank.example.com</a><a href=\"http://3221225985/\">x</a>"),
            plain("https://offer.example.net/x"),
            Fixture::message(""),
        ],
    )
    .await;
}
