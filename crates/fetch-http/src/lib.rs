//! [`Fetch`] over HTTPS with reqwest.

use std::time::Duration;

use async_trait::async_trait;
use pellet_fetch::{Fetch, FetchError};

/// Downloads with one shared reqwest client that identifies itself as Pellet. The body is read
/// chunk by chunk and dropped as soon as it passes `max_size`; reqwest errors are reported
/// without their URL.
pub struct HttpFetch {
    client: reqwest::Client,
}

impl HttpFetch {
    /// A client identifying itself as Pellet.
    pub fn new() -> Result<Self, FetchError> {
        reqwest::Client::builder()
            .user_agent(concat!("pellet/", env!("CARGO_PKG_VERSION")))
            .build()
            .map(|client| HttpFetch { client })
            .map_err(|e| FetchError::Download(e.to_string()))
    }
}

#[async_trait]
impl Fetch for HttpFetch {
    async fn fetch(
        &self,
        url: &str,
        timeout: Duration,
        max_size: usize,
    ) -> Result<Vec<u8>, FetchError> {
        let mut response = self
            .client
            .get(url)
            .timeout(timeout)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| FetchError::Download(e.without_url().to_string()))?;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| FetchError::Download(e.without_url().to_string()))?
        {
            if body.len() + chunk.len() > max_size {
                return Err(FetchError::TooLarge(max_size));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests;
