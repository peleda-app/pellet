#![no_main]

use libfuzzer_sys::fuzz_target;
use pellet_classifier::{Document, MAX_TOKENS, MIN_BITS, Model, Params, tokens};

fuzz_target!(|data: &[u8]| {
    let _ = Model::from_bytes(data);

    let mut bytes = Model::new(Params {
        bits: MIN_BITS,
        ..Params::default()
    })
    .expect("model")
    .to_bytes();
    for pair in data.chunks_exact(4) {
        let at = u32::from_le_bytes([pair[0], pair[1], pair[2], 0]) as usize % bytes.len();
        bytes[at] ^= pair[3];
    }
    let _ = Model::from_bytes(&bytes);

    let text = String::from_utf8_lossy(data);
    let mut parts = text.split('\u{1}');
    let mut next = || parts.next().unwrap_or_default().to_owned();
    let doc = Document {
        subject: next(),
        body: next(),
        domains: next().split(',').map(str::to_owned).collect(),
        sender_domain: next(),
        headers: next().split(',').map(str::to_owned).collect(),
        symbols: next().split(',').map(str::to_owned).collect(),
    };
    assert!(tokens(&doc).len() <= MAX_TOKENS);
});
