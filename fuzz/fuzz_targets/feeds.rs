#![no_main]

use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use pellet_rules::{HttpList, ListFormat};

fuzz_target!(|data: &[u8]| {
    let Some((&mode, body)) = data.split_first() else {
        return;
    };
    let format = if mode & 1 == 0 {
        ListFormat::Lines
    } else {
        ListFormat::Csv {
            separator: [',', ';', '\t', '|'][(mode >> 1) as usize & 3],
            key: (mode >> 3) as usize & 3,
            skip_first: mode & 0x20 != 0,
        }
    };
    let list = HttpList {
        id: "FUZZ_LIST".into(),
        name: "fuzz_list".into(),
        url: "https://lists.example.net/list.txt".into(),
        format,
        gzipped: mode & 0x40 != 0,
        refresh: Duration::from_secs(3600),
        retry: Duration::from_secs(60),
        timeout: Duration::from_secs(10),
        max_size: 1 << 20,
        max_entries: 1000,
        max_entry_size: 256,
    };
    if let Ok(prints) = pellet_feeds::parse(&list, body, 500) {
        assert!(prints.len() <= 500);
    }
});
