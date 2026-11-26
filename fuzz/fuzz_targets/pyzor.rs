#![no_main]

use libfuzzer_sys::fuzz_target;
use pellet_check_pyzor::{digest, testing::parse_response};
use pellet_core::Message;

fuzz_target!(|data: &[u8]| {
    if let Some(hex) = digest(&Message::new(data)) {
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
    }
    let thread = data.first().copied().unwrap_or(0) as u16;
    let _ = parse_response(&String::from_utf8_lossy(data), thread);
});
