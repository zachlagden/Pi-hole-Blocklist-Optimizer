use anyhow::{anyhow, Result};
use log::debug;
use reqwest::header;
use reqwest::Client;
use reqwest::StatusCode;
use std::time::Duration;

const MAX_RETRIES: u32 = 3;
const RETRY_BACKOFF_MS: u64 = 500;
const RETRY_STATUS_CODES: &[u16] = &[429, 500, 502, 503, 504];
const USER_AGENT: &str = "Pi-hole Blocklist Optimizer/3.0";

#[derive(Clone)]
pub struct HttpClient {
    client: Client,
}

pub struct DownloadResult {
    pub content: Option<Vec<u8>>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub was_modified: bool,
}

impl HttpClient {
    pub fn new(timeout_secs: u64) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .user_agent(USER_AGENT)
            .gzip(true)
            .brotli(true)
            .build()?;

        Ok(Self { client })
    }

    pub async fn download(
        &self,
        url: &str,
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> Result<DownloadResult> {
        let mut attempts = 0u32;

        loop {
            let mut request = self.client.get(url);

            if let Some(etag) = etag {
                request = request.header(header::IF_NONE_MATCH, etag);
            }
            if let Some(lm) = last_modified {
                request = request.header(header::IF_MODIFIED_SINCE, lm);
            }

            match request.send().await {
                Ok(response) => {
                    let status = response.status();

                    if status == StatusCode::NOT_MODIFIED {
                        return Ok(DownloadResult {
                            content: None,
                            etag: etag.map(String::from),
                            last_modified: last_modified.map(String::from),
                            was_modified: false,
                        });
                    }

                    if RETRY_STATUS_CODES.contains(&status.as_u16()) && attempts < MAX_RETRIES {
                        attempts += 1;
                        let delay = RETRY_BACKOFF_MS * 2u64.pow(attempts - 1);
                        debug!(
                            "Retry {attempts}/{MAX_RETRIES} for {url} (HTTP {status}), waiting {delay}ms"
                        );
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                        continue;
                    }

                    if !status.is_success() {
                        return Err(anyhow!("HTTP {status} for {url}"));
                    }

                    let new_etag = response
                        .headers()
                        .get(header::ETAG)
                        .and_then(|v| v.to_str().ok())
                        .map(String::from);
                    let new_last_modified = response
                        .headers()
                        .get(header::LAST_MODIFIED)
                        .and_then(|v| v.to_str().ok())
                        .map(String::from);

                    let content = response.bytes().await?.to_vec();

                    return Ok(DownloadResult {
                        content: Some(content),
                        etag: new_etag,
                        last_modified: new_last_modified,
                        was_modified: true,
                    });
                }
                Err(e) => {
                    if attempts < MAX_RETRIES {
                        attempts += 1;
                        let delay = RETRY_BACKOFF_MS * 2u64.pow(attempts - 1);
                        debug!(
                            "Retry {attempts}/{MAX_RETRIES} for {url} ({e}), waiting {delay}ms"
                        );
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    } else {
                        return Err(e.into());
                    }
                }
            }
        }
    }
}
