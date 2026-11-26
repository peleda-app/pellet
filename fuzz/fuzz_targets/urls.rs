#![no_main]

use libfuzzer_sys::fuzz_target;
use pellet_core::Message;
use pellet_urls::{MAX_LINKS, Url, from_html, from_text, message_links, percent_decode};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    assert!(from_text(&text).len() <= MAX_LINKS);
    assert!(from_html(&text).len() <= MAX_LINKS);
    if let Some(url) = Url::parse(&text) {
        let _ = format!("{url:?}");
    }
    let _ = percent_decode(&text);
    let _ = message_links(&Message::new(data));
});
