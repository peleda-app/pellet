#![no_main]

mod common;

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use pellet_check::{Check, testing::Fixture};
use pellet_check_auth::{AuthCheck, AuthConfig};
use pellet_core::{Message, Stage};

const NAMES: [&str; 4] = [
    "example.com",
    "_dmarc.example.com",
    "sel._domainkey.example.com",
    "example.org",
];

fn check() -> &'static AuthCheck {
    static CHECK: OnceLock<AuthCheck> = OnceLock::new();
    CHECK.get_or_init(|| {
        AuthCheck::new(&AuthConfig {
            nameservers: vec!["127.0.0.1".parse().expect("address")],
            cache_entries: 64,
            ..AuthConfig::default()
        })
        .expect("auth")
    })
}

// The input is a DNS TXT record, a NUL, then an envelope and message as in `common`; the
// record's first byte picks which of `NAMES` it answers for.
fuzz_target!(|data: &[u8]| {
    let Some(nul) = data.iter().position(|&b| b == 0) else {
        return;
    };
    let (record, rest) = (&data[..nul], &data[nul + 1..]);
    if let Some((&pick, record)) = record.split_first() {
        let record = String::from_utf8_lossy(record);
        check().add_txt_record(NAMES[pick as usize % NAMES.len()], &record);
    }
    let (envelope, raw) = common::envelope_and_message(rest);
    let fixture = Fixture {
        envelope,
        message: Some(Message::new(raw)),
        earlier: Vec::new(),
    };
    let ctx = fixture.context(Stage::Data);
    let _ = common::runtime().block_on(check().run(&ctx));
});
