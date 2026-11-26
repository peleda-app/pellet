use std::time::Duration;

use async_trait::async_trait;

use crate::testing::{BODY, LARGE_LEN, SLOW_DELAY, Urls};
use crate::{Fetch, FetchError};

struct MemoryFetch;

#[async_trait]
impl Fetch for MemoryFetch {
    async fn fetch(
        &self,
        url: &str,
        timeout: Duration,
        max_size: usize,
    ) -> Result<Vec<u8>, FetchError> {
        let body = match url {
            "mem://ok" => BODY.to_vec(),
            "mem://large" => vec![0; LARGE_LEN],
            "mem://slow" if timeout < SLOW_DELAY => {
                return Err(FetchError::Download("timed out".into()));
            }
            "mem://slow" => BODY.to_vec(),
            "mem://missing" => return Err(FetchError::Download("status 404".into())),
            _ => return Err(FetchError::Download("unusable URL".into())),
        };
        if body.len() > max_size {
            return Err(FetchError::TooLarge(max_size));
        }
        Ok(body)
    }
}

struct LeakyFetch;

#[async_trait]
impl Fetch for LeakyFetch {
    async fn fetch(
        &self,
        url: &str,
        timeout: Duration,
        max_size: usize,
    ) -> Result<Vec<u8>, FetchError> {
        match url {
            "mem://missing" => Err(FetchError::Download(format!("404 at {url}"))),
            _ => MemoryFetch.fetch(url, timeout, max_size).await,
        }
    }
}

fn urls() -> Urls {
    Urls {
        ok: "mem://ok".into(),
        large: "mem://large".into(),
        missing: "mem://missing".into(),
        slow: "mem://slow".into(),
    }
}

#[tokio::test]
async fn a_faithful_fetch_passes() {
    crate::testing::conformance(&MemoryFetch, &urls()).await;
}

#[tokio::test]
#[should_panic(expected = "carries the URL")]
async fn a_fetch_that_leaks_the_url_fails() {
    crate::testing::conformance(&LeakyFetch, &urls()).await;
}

#[test]
fn errors_say_what_failed() {
    assert_eq!(FetchError::TooLarge(64).to_string(), "larger than 64 bytes");
    assert_eq!(
        FetchError::Download("refused".into()).to_string(),
        "download failed: refused"
    );
}
