//! Logging the CLI into a Help Peer website with an API token, so it can
//! send to usernames, read the inbox, and use the site's relay and storage
//! nodes. The login is stored in a config file shared with the Python SDK:
//! `$HELPEER_CONFIG`, else `$XDG_CONFIG_HOME/helppeer/config.json`
//! (`~/.config/...`), or `%APPDATA%\helppeer\config.json` on Windows.

use std::path::PathBuf;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Serialize, Deserialize, Clone)]
pub struct Login {
    pub server: String,
    pub token: String,
}

pub fn config_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("HELPEER_CONFIG") {
        return Some(PathBuf::from(p));
    }
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    };
    base.map(|b| b.join("helppeer").join("config.json"))
}

/// The saved login, if any.
pub fn load() -> Option<Login> {
    let data = std::fs::read(config_path()?).ok()?;
    serde_json::from_slice(&data).ok()
}

/// Save a login. The file holds a credential, so it's only readable by the user.
pub fn save(login: &Login) -> Result<PathBuf, String> {
    let path = config_path().ok_or("can't find a config directory (set HELPEER_CONFIG)")?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {}", dir.display(), e))?;
    }
    let data = serde_json::to_vec_pretty(login).unwrap();
    write_private(&path, &data).map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
    Ok(path)
}

#[cfg(unix)]
fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)
}

#[cfg(not(unix))]
fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, data)
}

pub fn remove() -> Result<bool, String> {
    let Some(path) = config_path() else { return Ok(false) };
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("cannot remove {}: {}", path.display(), e)),
    }
}

/// A client for the website's API, authenticated with the saved token.
pub struct Api {
    client: Client,
    login: Login,
}

impl Api {
    pub fn new(client: Client, login: Login) -> Self {
        Api { client, login }
    }

    async fn call(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Result<Value, String> {
        let url = format!("{}{}", self.login.server.trim_end_matches('/'), path);
        let mut req = self.client.request(method, &url).bearer_auth(&self.login.token);
        if let Some(b) = body {
            req = req.header("Content-Type", "application/json").body(b.to_string());
        }
        let resp = req.send().await.map_err(|e| format!("{} failed: {}", url, e))?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| format!("{} failed: {}", url, e))?;
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        if !status.is_success() {
            let msg = value["error"].as_str().map(str::to_string).unwrap_or_else(|| status.to_string());
            return Err(msg);
        }
        Ok(value)
    }

    /// Who the token belongs to: (email, username).
    pub async fn whoami(&self) -> Result<(String, String), String> {
        let me = self.call(reqwest::Method::GET, "/api/auth/me", None).await?;
        if me["authenticated"] != Value::Bool(true) {
            return Err("the server didn't accept this token (it may have been revoked)".into());
        }
        Ok((
            me["email"].as_str().unwrap_or_default().to_string(),
            me["username"].as_str().unwrap_or_default().to_string(),
        ))
    }

    /// The relay URL and storage nodes the website uses.
    pub async fn server_config(&self) -> Result<(String, Vec<String>), String> {
        let cfg = self.call(reqwest::Method::GET, "/api/config", None).await?;
        let relay = cfg["relay_url"].as_str().ok_or("server config has no relay_url")?.to_string();
        let nodes = cfg["storage_nodes"]
            .as_array()
            .map(|a| a.iter().filter_map(|n| n.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        Ok((relay, nodes))
    }

    pub async fn username_exists(&self, username: &str) -> Result<bool, String> {
        let path = format!("/api/users/lookup?username={}", urlencode(username));
        Ok(self.call(reqwest::Method::GET, &path, None).await?["exists"] == Value::Bool(true))
    }

    /// Register a transfer this CLI sent, then notify recipients (usernames
    /// go to their inbox; emails get the code by email). Returns the
    /// server's response, including any per-recipient errors.
    pub async fn notify(
        &self,
        relay_hash: &str,
        code: &str,
        transfer_name: &str,
        files: usize,
        total_bytes: u64,
        recipients: &[String],
    ) -> Result<Value, String> {
        let reg = self
            .call(
                reqwest::Method::POST,
                "/api/transfers",
                Some(json!({
                    "manifest_hash": relay_hash,
                    "transfer_name": transfer_name,
                    "files": files,
                    "total_bytes": total_bytes,
                })),
            )
            .await?;
        self.call(
            reqwest::Method::POST,
            "/api/notify",
            Some(json!({
                "transfer_id": reg["transfer_id"],
                "manifest_hash": relay_hash,
                "code": code,
                "recipients": recipients,
            })),
        )
        .await
    }

    pub async fn inbox(&self) -> Result<Vec<Value>, String> {
        let v = self.call(reqwest::Method::GET, "/api/inbox", None).await?;
        Ok(v["items"].as_array().cloned().unwrap_or_default())
    }

    /// Clear inbox items for a transfer we just received.
    pub async fn mark_received(&self, relay_hash: &str) -> Result<(), String> {
        self.call(
            reqwest::Method::POST,
            "/api/inbox/received",
            Some(json!({ "manifest_hash": relay_hash })),
        )
        .await
        .map(|_| ())
    }
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{:02X}", b),
        })
        .collect()
}

/// A recipient is an email address if it has an '@' after the first
/// character; otherwise it's a username ("alice" or "@alice").
pub fn is_email(recipient: &str) -> bool {
    recipient.find('@').map_or(false, |i| i > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_email() {
        assert!(is_email("a@b.com"));
        assert!(!is_email("@alice"));
        assert!(!is_email("alice"));
    }

    #[test]
    fn test_save_load_remove() {
        let dir = std::env::temp_dir().join("helppeer_account_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("HELPEER_CONFIG", dir.join("config.json"));

        let path = save(&Login { server: "https://x".into(), token: "hp_t".into() }).unwrap();
        assert_eq!(load().unwrap().token, "hp_t");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert!(remove().unwrap());
        assert!(load().is_none());

        std::env::remove_var("HELPEER_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
