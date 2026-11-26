#![no_main]

use libfuzzer_sys::fuzz_target;
use pellet_core::Message;

fuzz_target!(|data: &[u8]| {
    let message = Message::new(data);
    for header in message.headers() {
        let _ = header.value_str();
        let _ = message.header(header.name());
        let _ = message.header_count(header.name());
    }
    assert!(message.body().len() <= data.len());
    let _ = message.malformed_header_lines();
    let _ = message.headers_truncated();
});
