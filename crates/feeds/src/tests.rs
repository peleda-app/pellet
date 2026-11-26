use std::{
    io::Write,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use flate2::{Compression, write::GzEncoder};
use pellet_rules::RuleSet;

use super::*;

fn list(name: &str) -> HttpList {
    RuleSet::bundled()
        .unwrap()
        .http_lists()
        .iter()
        .find(|l| l.name == name)
        .unwrap()
        .clone()
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pellet-feeds-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct FakeFetch {
    body: Mutex<Result<Vec<u8>, FetchError>>,
    calls: AtomicUsize,
}

impl FakeFetch {
    fn answering(body: &str) -> Self {
        FakeFetch {
            body: Mutex::new(Ok(body.as_bytes().to_vec())),
            calls: AtomicUsize::new(0),
        }
    }

    fn failing() -> Self {
        FakeFetch {
            body: Mutex::new(Err(FetchError::Download("refused".into()))),
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Fetch for FakeFetch {
    async fn fetch(
        &self,
        _url: &str,
        _timeout: Duration,
        _max_size: usize,
    ) -> Result<Vec<u8>, FetchError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.body.lock().unwrap().clone()
    }
}

#[test]
fn parses_line_lists() {
    let openphish = list("stwt_openphish");
    let parsed = parse(
        &openphish,
        b"# comment\nhttps://phish.example.net/a\n\nhttps://phish.example.net/b\n",
        usize::MAX,
    )
    .unwrap();
    assert_eq!(parsed.len(), 2);
    assert!(parsed.contains("https://PHISH.example.net/a"));
}

#[test]
fn parses_gzipped_csv_with_a_header() {
    let phishtank = list("stwt_phishtank");
    let csv = "phish_id,url,phish_detail_url\n1,\"https://login.example.info/x\",d\n2,https://bank.example.org/y,d\n";
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(csv.as_bytes()).unwrap();
    let parsed = parse(&phishtank, &encoder.finish().unwrap(), usize::MAX).unwrap();
    assert_eq!(parsed.len(), 2);
    assert!(parsed.contains("https://login.example.info/x"));
    assert!(!parsed.contains("url"), "the header is skipped");
    assert!(matches!(
        parse(&phishtank, b"not gzip", usize::MAX),
        Err(FeedError::Content(_))
    ));
}

#[test]
fn bounds_hold() {
    let mut small = list("stwt_openphish");
    let body: String = (0..1000)
        .map(|i| format!("https://h{i}.example/\n"))
        .collect();
    assert_eq!(
        parse(&small, body.as_bytes(), 100).unwrap().len(),
        100,
        "the deployment cap wins"
    );
    small.max_entry_size = 10;
    assert!(
        matches!(
            parse(&small, body.as_bytes(), 100),
            Err(FeedError::Content(_))
        ),
        "every key too long"
    );
    let mut gz = list("stwt_phishtank");
    gz.max_size = 64;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&vec![b'a'; 10_000]).unwrap();
    assert_eq!(
        parse(&gz, &encoder.finish().unwrap(), usize::MAX),
        Err(FeedError::TooLarge(64))
    );
}

#[test]
fn cache_round_trip() {
    let dir = temp_dir("cache");
    let path = dir.join("x.fp");
    let original = Fingerprints::from_keys(["a.example", "b.example"]);
    save(&path, &original).unwrap();
    let (loaded, _) = load(&path).unwrap();
    assert_eq!(loaded, original);
    std::fs::write(&path, b"PELLETF1broken").unwrap();
    assert!(load(&path).is_none());
    assert!(load(&dir.join("missing.fp")).is_none());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn refresh_publishes_and_caches() {
    let dir = temp_dir("refresh");
    let openphish = list("stwt_openphish");
    let remote = RemoteLists::default();
    let fetch = FakeFetch::answering("https://phish.example.net/a\n");
    assert_eq!(
        refresh(&openphish, &fetch, &remote, &dir, usize::MAX).await,
        Ok(1)
    );
    assert_eq!(remote.len("stwt_openphish"), 1);
    assert!(cache_path(&dir, &openphish).exists());

    let restored = RemoteLists::default();
    let wait = restore(&openphish, &restored, &dir);
    assert_eq!(restored.len("stwt_openphish"), 1);
    assert!(
        wait > openphish.refresh - Duration::from_secs(60),
        "a fresh cache is not due"
    );
    assert_eq!(
        refresh(&openphish, &FakeFetch::failing(), &remote, &dir, usize::MAX).await,
        Err(FeedError::Download("refused".into()))
    );
    assert_eq!(
        remote.len("stwt_openphish"),
        1,
        "a failure keeps the last good copy"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(start_paused = true)]
async fn keeps_lists_fresh_on_schedule() {
    let dir = temp_dir("schedule");
    let mut openphish = list("stwt_openphish");
    openphish.refresh = Duration::from_secs(100);
    openphish.retry = Duration::from_secs(10);
    let remote = RemoteLists::default();
    let fetch = Arc::new(FakeFetch::failing());
    let task = tokio::spawn(keep_fresh(
        openphish.clone(),
        fetch.clone(),
        remote.clone(),
        dir.clone(),
        usize::MAX,
    ));
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(fetch.calls(), 1, "no cache: fetched at once");
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(fetch.calls(), 2, "a failure retries after `retry`");
    *fetch.body.lock().unwrap() = Ok(b"https://phish.example.net/a\n".to_vec());
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(fetch.calls(), 3);
    assert_eq!(remote.len("stwt_openphish"), 1);
    tokio::time::sleep(Duration::from_secs(50)).await;
    assert_eq!(fetch.calls(), 3, "a success waits `refresh`");
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(fetch.calls(), 4);
    task.abort();
    std::fs::remove_dir_all(&dir).unwrap();
}
