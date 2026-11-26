use std::time::Duration;

use pellet_core::Action;

use super::*;

#[test]
fn bundled_data_loads_completely() {
    let set = RuleSet::bundled().unwrap();
    assert_eq!(set.rules().len(), 66, "every [rule.*] table");
    assert_eq!(set.dnsbl().len(), 17, "every enabled [dnsbl.*] table");
    assert_eq!(set.http_lists().len(), 4);
    assert!(set.scores().len() > 400, "{}", set.scores().len());
    assert!(set.lists().len("url-redirectors") > 1000);
    assert!(set.lists().contains("click-trackers", "awstrack.me"));
    assert!(
        set.lists()
            .contains("alias-relays", "privaterelay.appleid.com")
    );
    assert!(set.lists().contains("trusted-domains", "126.com"));
    assert_eq!(set.lists().value("file-extensions", "bat"), Some("BAD"));
    assert!(set.http_lists().iter().any(|l| l.name == "stwt_openphish"));
    assert_eq!(
        set.scores()
            .score(&SymbolName::new("REPUTATION_IP_SPAM").unwrap()),
        3.0,
        "Pellet's own scores"
    );
}

#[test]
fn referenced_symbols_include_header_presence() {
    let referenced = RuleSet::bundled().unwrap().referenced_symbols();
    assert!(referenced.contains("X_HDR_LIST_UNSUBSCRIBE"));
    assert!(referenced.contains("DMARC_POLICY_ALLOW"));
}

#[test]
fn dnsbl_symbols_come_from_tags() {
    let symbols = RuleSet::bundled().unwrap().dnsbl_symbols();
    for name in [
        "RBL_SPAMHAUS_SBL",
        "RECEIVED_SPAMHAUS_SBL",
        "DBL_PHISH",
        "SURBL_HASHBL_PHISH",
        "MSBL_EBL",
    ] {
        assert!(symbols.iter().any(|s| s.as_str() == name), "{name}");
    }
}

#[test]
fn rules_run_in_priority_order() {
    let set = RuleSet::bundled().unwrap();
    let priorities: Vec<i64> = set.rules().iter().map(|r| r.priority).collect();
    let mut sorted = priorities.clone();
    sorted.sort();
    assert_eq!(priorities, sorted);
}

#[test]
fn symbols_include_literal_and_prefixed_results() {
    let set = RuleSet::bundled().unwrap();
    let symbols = set.symbols(&[Scope::Any, Scope::Email]);
    for name in [
        "SUBJ_BOUNCE_WORDS",
        "FAKE_REPLY",
        "AUTH_NA_OR_FAIL",
        "TAGGED_RCPT",
        "FREEMAIL_FROM",
    ] {
        assert!(symbols.contains(&SymbolName::new(name).unwrap()), "{name}");
    }
    assert!(
        !symbols.iter().any(|s| s.as_str() == "FREEMAIL_"),
        "prefixes are not symbols"
    );
    assert!(
        !symbols.iter().any(|s| s.as_str() == "PHISHED_OPENPHISH"),
        "url scope excluded"
    );
}

fn load(text: &str) -> Result<RuleSet, DataError> {
    let mut set = RuleSet::default();
    set.add_rules("test.toml", text)?;
    Ok(set)
}

#[test]
fn refuses_broken_rules_with_their_id() {
    for (text, message) in [
        (
            "[rule.A]\nscope = \"any\"\ncondition = \"contains(subject\"\n",
            "else",
        ),
        (
            "[rule.A]\nscope = \"nowhere\"\ncondition = false\n",
            "unknown scope",
        ),
        ("[rule.A]\ncondition = false\n", "missing `scope`"),
        ("[rule.A]\nscope = \"any\"\n", "missing `condition`"),
        (
            "[rule.A]\nscope = \"any\"\ncondition = \"name_lower == 'x'\"\n",
            "variable `name_lower`",
        ),
        (
            "[rule.A]\nscope = \"any\"\ncondition = false\ncolour = 1\n",
            "unknown key",
        ),
        (
            "[rule.A]\nscope = \"any\"\ncondition = [ { if = \"true\" } ]\n",
            "needs `if` and `then`",
        ),
        ("[thing.A]\nscope = \"any\"\n", "unknown table kind"),
    ] {
        let error = load(text).unwrap_err();
        assert_eq!(error.file, "test.toml");
        assert!(error.to_string().contains(message), "{text}: {error}");
    }
}

#[test]
fn disabled_rules_are_checked_but_left_out() {
    let set = load("[rule.A]\nscope = \"any\"\nenable = false\ncondition = \"'A'\"\n").unwrap();
    assert!(set.rules().is_empty());
    assert!(load("[rule.A]\nscope = \"any\"\nenable = false\ncondition = \"nope(\"\n").is_err());
}

#[test]
fn header_rules_may_read_header_variables() {
    let set = load(
        "[rule.A]\nscope = \"header\"\ncondition = [ { if = \"name_lower == 'x-a' && contains(subject, 'b')\", then = \"'A'\" }, { else = false } ]\n",
    )
    .unwrap();
    assert_eq!(set.rules()[0].scope, Scope::Header);
}

#[test]
fn scores_parse_and_refuse_garbage() {
    let mut set = RuleSet::default();
    set.add_scores("s.txt", "# comment\n\nA = 1.5\nB = -0.5\nA = 2\n")
        .unwrap();
    assert_eq!(set.scores().score(&SymbolName::new("A").unwrap()), 2.0);
    assert_eq!(set.scores().len(), 2);
    set.add_scores("s.txt", "BLOCKED = reject\n").unwrap();
    assert_eq!(
        set.scores().forced(&SymbolName::new("BLOCKED").unwrap()),
        Some(Action::Reject)
    );
    for bad in ["A 1", "a = 1", "A = x", "A = inf", "A = accept"] {
        let error = set.add_scores("s.txt", bad).unwrap_err();
        assert_eq!(error.item, "line 1", "{bad}");
    }
}

#[test]
fn lists_from_text() {
    let mut lists = Lists::default();
    lists.insert_text("ext", "# c\nEXE = BAD\n\nzip\n");
    assert!(lists.contains("ext", "exe"));
    assert_eq!(lists.value("ext", "exe"), Some("BAD"));
    assert!(lists.contains("ext", "zip"));
    assert!(!lists.contains("ext", "# c"));
    assert!(!lists.contains("missing", "zip"));
    assert_eq!(lists.len("ext"), 2);
    let mut entries: Vec<(&str, &str)> = lists.entries("ext").collect();
    entries.sort();
    assert_eq!(entries, [("exe", "BAD"), ("zip", "")]);
    assert_eq!(lists.entries("missing").count(), 0);
}

#[test]
fn http_lists_read_their_settings() {
    let set = RuleSet::bundled().unwrap();
    let phishtank = set
        .http_lists()
        .iter()
        .find(|l| l.name == "stwt_phishtank")
        .unwrap();
    assert_eq!(
        phishtank.format,
        ListFormat::Csv {
            separator: ',',
            key: 1,
            skip_first: true
        }
    );
    assert!(phishtank.gzipped);
    assert_eq!(phishtank.refresh, Duration::from_secs(6 * 3600));
    assert_eq!(phishtank.max_entries, 900_000);
    let openphish = set
        .http_lists()
        .iter()
        .find(|l| l.name == "stwt_openphish")
        .unwrap();
    assert_eq!(openphish.format, ListFormat::Lines);
    assert!(!openphish.gzipped);
    let bad = RuleSet::default().clone().add_rules(
        "x.toml",
        "[http-list.X]\nurl = \"https://example.com/\"\nformat = \"xml\"\n",
    );
    assert!(bad.is_err());
}

#[test]
fn remote_lists_are_shared_by_clones() {
    let set = RuleSet::bundled().unwrap();
    let copy = set.clone();
    assert!(
        !copy
            .lists()
            .contains("stwt_openphish", "https://phish.example.net/login")
    );
    set.lists().remote().set(
        "stwt_openphish",
        Fingerprints::from_keys(["https://PHISH.example.net/login "]),
    );
    assert!(
        copy.lists()
            .contains("stwt_openphish", "https://phish.example.net/login")
    );
    assert_eq!(set.lists().remote().len("stwt_openphish"), 1);
    assert_eq!(set.lists().remote().len("missing"), 0);
}

#[test]
fn fingerprints() {
    let list = Fingerprints::from_keys(["b.example", "a.example", "B.example"]);
    assert_eq!(list.len(), 2);
    assert!(list.contains(" A.EXAMPLE"));
    assert!(!list.contains("c.example"));
    assert!(list.as_slice().windows(2).all(|w| w[0] < w[1]));
    assert_eq!(fingerprint("x"), fingerprint(" X "));
}
