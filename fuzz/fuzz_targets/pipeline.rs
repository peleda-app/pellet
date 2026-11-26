#![no_main]

mod common;

use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use pellet_check_auth::{AuthCheck, AuthConfig};
use pellet_check_classifier::{ClassifierCheck, ClassifierConfig};
use pellet_check_content::{
    AddressCheck, DateCheck, EncodingCheck, HeaderFlagsCheck, HeaderPresenceCheck, HeadersCheck,
    HtmlCheck, MessageIdCheck, MimeCheck, ReceivedCheck, SubjectCheck,
};
use pellet_check_ip::{
    DnsblCheck, DnsblResult, DnsblZone, FromHostCheck, HeloCheck, ReverseDnsCheck,
};
use pellet_check_reputation::{
    ReplyCheck, ReplyConfig, ReputationCheck, ReputationConfig, TrapCheck,
};
use pellet_check_rules::{DnsListCheck, RulesCheck};
use pellet_check_url::UrlCheck;
use pellet_classifier::{MIN_BITS, Model, Params};
use pellet_core::{Message, SymbolName};
use pellet_dns::{Resolver, testing::FakeResolver};
use pellet_engine::Engine;
use pellet_rules::RuleSet;
use pellet_state_memory::MemoryState;

fn engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let rules = Arc::new(RuleSet::bundled().expect("bundled rules"));
        let resolver: Arc<dyn Resolver> = Arc::new(
            FakeResolver::new()
                .with_ipv4("mail.example.com", &["192.0.2.1"])
                .with_ptr("192.0.2.1", &["mail.example.com"])
                .with_mx("example.com", &[(10, "mail.example.com")]),
        );
        let state = Arc::new(MemoryState::new(10_000));
        let auth = AuthCheck::new(&AuthConfig {
            nameservers: vec!["127.0.0.1".parse().expect("address")],
            cache_entries: 256,
            ..AuthConfig::default()
        })
        .expect("auth");
        auth.add_txt_record("example.com", "v=spf1 ip4:192.0.2.0/24 -all");
        auth.add_txt_record("_dmarc.example.com", "v=DMARC1; p=reject");
        let zone = DnsblZone {
            zone: "dnsbl.example.net".into(),
            ipv6: true,
            results: vec![DnsblResult {
                codes: 2..=2,
                symbol: SymbolName::new("RBL_EXAMPLE").expect("name"),
            }],
        };
        Engine::builder()
            .check(Arc::new(DnsblCheck::new(resolver.clone(), vec![zone])))
            .check(Arc::new(ReverseDnsCheck::new(resolver.clone())))
            .check(Arc::new(HeloCheck::new(resolver.clone())))
            .check(Arc::new(FromHostCheck::new(resolver.clone())))
            .check(Arc::new(HeadersCheck::new()))
            .check(Arc::new(HeaderPresenceCheck::from_symbols(
                rules.referenced_symbols(),
            )))
            .check(Arc::new(HeaderFlagsCheck::new()))
            .check(Arc::new(AddressCheck::new()))
            .check(Arc::new(EncodingCheck::new()))
            .check(Arc::new(MessageIdCheck::new()))
            .check(Arc::new(DateCheck::new()))
            .check(Arc::new(ReceivedCheck::new()))
            .check(Arc::new(SubjectCheck::new()))
            .check(Arc::new(MimeCheck::new(
                rules.lists().entries("file-extensions"),
            )))
            .check(Arc::new(HtmlCheck::new()))
            .check(Arc::new(UrlCheck::new(
                rules
                    .lists()
                    .entries("url-redirectors")
                    .map(|(host, _)| host),
            )))
            .check(Arc::new(auth))
            .check(Arc::new(RulesCheck::new(rules.clone())))
            .check(Arc::new(DnsListCheck::new(rules.clone(), resolver)))
            .check(Arc::new(ClassifierCheck::new(
                Model::new(Params {
                    bits: MIN_BITS,
                    ..Params::default()
                })
                .expect("model"),
                ClassifierConfig {
                    min_ham: 0,
                    min_spam: 0,
                    auto_learn: false,
                    ..ClassifierConfig::default()
                },
            )))
            .check(Arc::new(ReputationCheck::new(
                state.clone(),
                ReputationConfig::default(),
            )))
            .check(Arc::new(TrapCheck::new(["trap@example.org"])))
            .check(Arc::new(ReplyCheck::new(state, ReplyConfig::default())))
            .scores(rules.scores().clone())
            .build()
            .expect("engine")
    })
}

fuzz_target!(|data: &[u8]| {
    let (envelope, raw) = common::envelope_and_message(data);
    let verdict = common::runtime().block_on(engine().check_message(envelope, Message::new(raw)));
    assert!(verdict.score.is_finite());
});
