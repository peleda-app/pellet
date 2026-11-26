//! Conformance suite for the `Fetch` contract.
//!
//! The harness serves four URLs and passes them in [`Urls`]:
//!
//! ```ignore
//! #[tokio::test]
//! async fn conformance() {
//!     let urls = serve().await;
//!     pellet_fetch::testing::conformance(&MyFetch::new(), &urls).await;
//! }
//! ```

use std::time::{Duration, Instant};

use crate::{Fetch, FetchError};

/// The body the `ok` URL serves.
pub const BODY: &[u8] = b"https://phish.example.net/a\n# comment\nhttps://phish.example.net/b\n";

/// The length of the body the `large` URL serves; any bytes will do.
pub const LARGE_LEN: usize = 256 * 1024;

/// How long the `slow` URL must wait before answering, at least.
pub const SLOW_DELAY: Duration = Duration::from_secs(10);

/// What the harness serves.
pub struct Urls {
    /// Answers 200 with [`BODY`].
    pub ok: String,
    /// Answers 200 with [`LARGE_LEN`] bytes.
    pub large: String,
    /// Answers 404.
    pub missing: String,
    /// Accepts the request and answers nothing for at least [`SLOW_DELAY`].
    pub slow: String,
}

const TIMEOUT: Duration = Duration::from_secs(5);

fn assert_quiet(error: &FetchError, url: &str) {
    assert!(
        !error.to_string().contains(url),
        "error message carries the URL: {error}"
    );
}

/// Every guarantee of [`Fetch`] against the served URLs.
pub async fn conformance(fetch: &dyn Fetch, urls: &Urls) {
    assert_eq!(
        fetch.fetch(&urls.ok, TIMEOUT, 1024).await.unwrap(),
        BODY,
        "body as served"
    );
    assert_eq!(
        fetch.fetch(&urls.ok, TIMEOUT, BODY.len()).await.unwrap(),
        BODY,
        "a body of exactly max_size is accepted"
    );
    assert_eq!(
        fetch.fetch(&urls.ok, TIMEOUT, BODY.len() - 1).await,
        Err(FetchError::TooLarge(BODY.len() - 1)),
        "one byte over max_size"
    );
    assert_eq!(
        fetch.fetch(&urls.large, TIMEOUT, 1024).await,
        Err(FetchError::TooLarge(1024)),
        "a large body is refused"
    );
    assert_eq!(
        fetch
            .fetch(&urls.large, TIMEOUT, LARGE_LEN)
            .await
            .unwrap()
            .len(),
        LARGE_LEN,
        "a large body within the limit is read whole"
    );

    match fetch.fetch(&urls.missing, TIMEOUT, 1024).await {
        Err(error @ FetchError::Download(_)) => assert_quiet(&error, &urls.missing),
        other => panic!("error status: {other:?}"),
    }

    for bad in ["", "not a url", "ftp://[::1"] {
        assert!(
            matches!(
                fetch.fetch(bad, TIMEOUT, 1024).await,
                Err(FetchError::Download(_))
            ),
            "unusable URL {bad:?}"
        );
    }

    let started = Instant::now();
    match fetch
        .fetch(&urls.slow, Duration::from_millis(200), 1024)
        .await
    {
        Err(error @ FetchError::Download(_)) => assert_quiet(&error, &urls.slow),
        other => panic!("deadline: {other:?}"),
    }
    assert!(
        started.elapsed() < SLOW_DELAY / 2,
        "the deadline ends the call, took {:?}",
        started.elapsed()
    );
}
