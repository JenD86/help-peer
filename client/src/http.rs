use std::time::Duration;

use reqwest::{Client, StatusCode};

const ATTEMPTS: u32 = 3;

/// Build the shared HTTP client. One client is reused for every request so
/// connections to the relay and storage nodes are pooled.
pub fn client() -> Result<Client, String> {
    Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| format!("failed to create HTTP client: {}", e))
}

/// Server errors and rate limiting are worth retrying; other failures are not.
fn retryable(status: StatusCode) -> bool {
    status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS
}

async fn backoff(attempt: u32) {
    if attempt > 0 {
        tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
    }
}

/// PUT `body` to `url`, retrying transient failures. `what` names the
/// request in error messages (URLs can contain the relay key).
pub async fn put(
    client: &Client,
    url: &str,
    body: &[u8],
    headers: &[(&str, &str)],
    what: &str,
) -> Result<(), String> {
    let mut last_err = String::new();
    for attempt in 0..ATTEMPTS {
        backoff(attempt).await;
        let mut req = client
            .put(url)
            .header("Content-Type", "application/octet-stream")
            .body(body.to_vec());
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        match req.send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp) if retryable(resp.status()) => {
                last_err = format!("{} returned status {}", what, resp.status())
            }
            Ok(resp) => return Err(format!("{} returned status {}", what, resp.status())),
            Err(e) => last_err = format!("{} failed: {}", what, e),
        }
    }
    Err(last_err)
}

/// POST `body` to `url`. Only retried when the request can't have reached
/// the server (connection failures or 429), since a POST may not be
/// idempotent: a lost response to a download confirmation must not lead to
/// confirming twice.
pub async fn post(client: &Client, url: &str, body: Vec<u8>, what: &str) -> Result<(), String> {
    let mut last_err = String::new();
    for attempt in 0..ATTEMPTS {
        backoff(attempt).await;
        match client.post(url).body(body.clone()).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp) if resp.status() == StatusCode::TOO_MANY_REQUESTS => {
                last_err = format!("{} returned status {}", what, resp.status())
            }
            Ok(resp) => return Err(format!("{} returned status {}", what, resp.status())),
            Err(e) if e.is_connect() => last_err = format!("{} failed: {}", what, e),
            Err(e) => return Err(format!("{} failed: {}", what, e)),
        }
    }
    Err(last_err)
}

/// GET `url`, retrying transient failures. Returns Ok(None) on 404.
pub async fn get(client: &Client, url: &str, what: &str) -> Result<Option<Vec<u8>>, String> {
    let mut last_err = String::new();
    for attempt in 0..ATTEMPTS {
        backoff(attempt).await;
        match client.get(url).send().await {
            Ok(resp) if resp.status() == StatusCode::NOT_FOUND => return Ok(None),
            Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                Ok(b) => return Ok(Some(b.to_vec())),
                Err(e) => last_err = format!("{} failed reading body: {}", what, e),
            },
            Ok(resp) if retryable(resp.status()) => {
                last_err = format!("{} returned status {}", what, resp.status())
            }
            Ok(resp) => return Err(format!("{} returned status {}", what, resp.status())),
            Err(e) => last_err = format!("{} failed: {}", what, e),
        }
    }
    Err(last_err)
}
