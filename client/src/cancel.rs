use std::sync::Arc;

use reqwest::{Client, StatusCode};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::crypto;
use crate::http;
use crate::manifest::Manifest;

/// Shard deletions to run at once.
const DELETE_CONCURRENCY: usize = 16;

pub struct CancelResult {
    pub transfer_name: String,
    pub shards_deleted: usize,
    /// Already expired or deleted.
    pub shards_already_gone: usize,
    /// Couldn't be deleted (node unreachable, or identical data shared with
    /// another transfer, which keeps its own delete token); they expire with the TTL.
    pub shards_failed: usize,
}

/// Withdraw a transfer before its TTL: remove the manifest from the relay so
/// nobody can start receiving it, then delete its shards using the
/// manifest's delete token.
pub async fn cancel_transfer(code: &str, relay_url: &str) -> Result<CancelResult, String> {
    let client = http::client()?;
    let (k_data, k_index) = crypto::derive_keys(code);
    let manifest_url = format!("{}/manifest/{}", relay_url, crypto::relay_hash(&k_index));

    let encrypted_manifest = http::get(&client, &manifest_url, "manifest download")
        .await?
        .ok_or("transfer not found: the code is wrong, it expired, or it was already received")?;
    let manifest = Manifest::from_json(&crypto::decrypt_segment(&k_data, &encrypted_manifest)?)?;
    manifest.validate()?;

    // Withdraw the manifest first so no new download can start. Not
    // retried after it may have reached the relay: a lost response would
    // turn a successful cancel into a confusing 404.
    let resp = client
        .delete(&manifest_url)
        .body(manifest.ack_secret.clone())
        .send()
        .await
        .map_err(|e| format!("cancel request failed: {}", e))?;
    if resp.status() != StatusCode::NO_CONTENT {
        return Err(format!("relay refused to cancel the transfer (status {})", resp.status()));
    }

    // Then delete every shard.
    let limit = Arc::new(Semaphore::new(DELETE_CONCURRENCY));
    let mut tasks = JoinSet::new();
    for shard in manifest.files.iter().flat_map(|f| &f.segments).flat_map(|s| &s.shards) {
        let client = client.clone();
        let limit = limit.clone();
        let url = format!("{}/shard/{}", shard.node, shard.hash);
        let token = manifest.delete_token.clone();
        tasks.spawn(async move {
            let _permit = limit.acquire_owned().await;
            delete_shard(&client, &url, &token).await
        });
    }

    let mut result = CancelResult {
        transfer_name: manifest.transfer_name.clone(),
        shards_deleted: 0,
        shards_already_gone: 0,
        shards_failed: 0,
    };
    while let Some(outcome) = tasks.join_next().await {
        match outcome {
            Ok(Ok(StatusCode::NO_CONTENT)) => result.shards_deleted += 1,
            Ok(Ok(StatusCode::NOT_FOUND)) => result.shards_already_gone += 1,
            _ => result.shards_failed += 1,
        }
    }
    Ok(result)
}

/// DELETE a shard, retrying network errors and server errors (deleting is
/// idempotent: a repeat just returns 404).
async fn delete_shard(client: &Client, url: &str, token: &str) -> Result<StatusCode, String> {
    let mut last_err = String::new();
    for attempt in 0..3u32 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(1 << attempt)).await;
        }
        match client.delete(url).header("X-Delete-Token", token).send().await {
            Ok(resp) if resp.status().is_server_error() => last_err = format!("status {}", resp.status()),
            Ok(resp) => return Ok(resp.status()),
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(last_err)
}
