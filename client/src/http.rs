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

/// GET `url`, retrying transient failures. Returns Ok(None) on 404. A body
/// larger than `max_bytes` is an error, so a server can't exhaust our memory.
pub async fn get(client: &Client, url: &str, what: &str, max_bytes: usize) -> Result<Option<Vec<u8>>, String> {
    let mut last_err = String::new();
    for attempt in 0..ATTEMPTS {
        backoff(attempt).await;
        match client.get(url).send().await {
            Ok(resp) if resp.status() == StatusCode::NOT_FOUND => return Ok(None),
            Ok(resp) if resp.status().is_success() => match read_limited(resp, max_bytes).await {
                Ok(b) => return Ok(Some(b)),
                Err(ReadError::TooLarge) => return Err(format!("{} is larger than {} bytes", what, max_bytes)),
                Err(ReadError::Http(e)) => last_err = format!("{} failed reading body: {}", what, e),
            },
            Ok(resp) if retryable(resp.status()) => {
                last_err = format!("{} returned status {}", what, resp.status())
            }
            Ok(resp) => return Err(format!("{} returned status {}", what, resp.status())),
            Err(e) => last_err = format!("{} failed: {}", what, with_causes(&e)),
        }
    }
    Err(last_err)
}

/// An error with its causes: reqwest's own message leaves out why a request
/// failed (e.g. a DNS resolver refusing an address).
pub fn with_causes(e: &dyn std::error::Error) -> String {
    let mut msg = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        msg = format!("{}: {}", msg, cause);
        source = cause.source();
    }
    msg
}

enum ReadError {
    TooLarge,
    Http(reqwest::Error),
}

async fn read_limited(mut resp: reqwest::Response, max_bytes: usize) -> Result<Vec<u8>, ReadError> {
    if resp.content_length().map_or(false, |n| n > max_bytes as u64) {
        return Err(ReadError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(ReadError::Http)? {
        if body.len() + chunk.len() > max_bytes {
            return Err(ReadError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
