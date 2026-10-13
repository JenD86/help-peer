//! Shard URLs come from the manifest, which the sender wrote (and, for
//! transfers sent to a username, the website relayed). Without checks a
//! malicious manifest could make a receiver send requests to its own network:
//! localhost services, the router, cloud metadata endpoints. So shards are
//! only fetched from the storage nodes the receiver itself configured, or from
//! nodes that resolve to public addresses, checked when each connection is
//! made so a hostname can't switch to an internal address later.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{redirect, Client, Url};

/// Check a manifest's node URL is a plain http(s) base URL. Where it may
/// point is decided at fetch time by [`NodeClients::for_node`].
pub fn check_node_url(node: &str) -> Result<Url, String> {
    let url = Url::parse(node).map_err(|_| "not a URL".to_string())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("not an http(s) URL".into());
    }
    if url.host().is_none() || !url.username().is_empty() || url.password().is_some() {
        return Err("invalid host".into());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("unexpected query or fragment".into());
    }
    Ok(url)
}

/// Whether `ip` is a globally routable unicast address (matching the web
/// backend's `isPublicIP`, plus the special-purpose ranges Go also excludes).
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            let s = v6.segments();
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80 // link-local
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64, embeds an IPv4 address
                || s[..6] == [0; 6]) // IPv4-compatible and other reserved ::/96
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(o[0] == 0
        || ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || o[0] >= 240 // reserved
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // carrier-grade NAT 100.64.0.0/10
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // IETF protocol assignments
        || (o[0] == 198 && (o[1] & 0xfe) == 18)) // benchmarking 198.18.0.0/15
}

/// Resolves hostnames to their public addresses only, so the connection is
/// made to an address that was checked.
struct PublicOnly;

impl Resolve for PublicOnly {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str().to_string();
            let addrs: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.filter(|a| is_public_ip(a.ip())).collect();
            if addrs.is_empty() {
                return Err(format!("refusing to connect to {}: not a public address", host).into());
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// HTTP clients for storage nodes named by a manifest.
pub struct NodeClients {
    trusted: Client,
    public: Client,
    trusted_origins: Vec<String>,
}

impl NodeClients {
    /// `configured` are the receiver's own storage nodes (flags, environment
    /// or login), which may be on a private network.
    pub fn new(configured: &[String]) -> Result<Self, String> {
        let build = |b: reqwest::ClientBuilder| {
            b.connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(300))
                // A node has no reason to redirect, and a redirect could point anywhere.
                .redirect(redirect::Policy::none())
                .build()
                .map_err(|e| format!("failed to create HTTP client: {}", e))
        };
        Ok(NodeClients {
            trusted: build(Client::builder())?,
            // No proxy: a proxy would make the connection itself, skipping the check.
            public: build(Client::builder().no_proxy().dns_resolver(Arc::new(PublicOnly)))?,
            trusted_origins: configured
                .iter()
                .filter_map(|n| Url::parse(n).ok())
                .map(|u| u.origin().ascii_serialization())
                .collect(),
        })
    }

    /// The client to fetch from `node` with, or an error if it may not be
    /// contacted at all.
    pub fn for_node(&self, node: &str) -> Result<&Client, String> {
        let url = check_node_url(node).map_err(|e| format!("storage node {:?}: {}", node, e))?;
        if self.trusted_origins.contains(&url.origin().ascii_serialization()) {
            return Ok(&self.trusted);
        }
        // IP addresses in the URL skip DNS, so the resolver can't check them.
        let host = url.host_str().unwrap_or_default().trim_start_matches('[').trim_end_matches(']');
        if host.parse::<IpAddr>().map_or(false, |ip| !is_public_ip(ip)) {
            return Err(format!(
                "storage node {} is a private or internal address; add it to --nodes / HELPEER_STORAGE_NODES if you trust it",
                node
            ));
        }
        Ok(&self.public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_public_ips() {
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700::1111", "::ffff:8.8.8.8"] {
            assert!(is_public_ip(ip.parse().unwrap()), "{} should be public", ip);
        }
        for ip in [
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
            "0.0.0.0", "255.255.255.255", "224.0.0.1", "240.0.0.1", "192.0.2.1", "198.18.0.1",
            "::1", "::", "fe80::1", "fd00::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254",
            "64:ff9b::a00:1", "::127.0.0.1", "2001:db8::1",
        ] {
            assert!(!is_public_ip(ip.parse().unwrap()), "{} should not be public", ip);
        }
    }

    #[test]
    fn test_check_node_url() {
        for ok in ["https://node.example.com", "http://1.2.3.4:7001", "https://example.com/node1"] {
            check_node_url(ok).unwrap();
        }
        for bad in ["", "n", "file:///etc/passwd", "ftp://example.com", "https://user:pw@example.com",
                    "https://example.com?x=1", "https://example.com#x"] {
            assert!(check_node_url(bad).is_err(), "accepted {:?}", bad);
        }
    }

    #[test]
    fn test_for_node() {
        let clients = NodeClients::new(&["http://127.0.0.1:7001".into(), "http://10.0.0.5:7001/".into()]).unwrap();
        // The receiver's own nodes may be private.
        assert!(clients.for_node("http://127.0.0.1:7001").is_ok());
        assert!(clients.for_node("http://10.0.0.5:7001").is_ok());
        // Anything else must not be a private IP...
        for bad in ["http://127.0.0.1:7002", "http://169.254.169.254", "http://[::1]:7001", "http://10.0.0.6:7001"] {
            assert!(clients.for_node(bad).is_err(), "allowed {}", bad);
        }
        // ...and hostnames go through the public-only resolver.
        assert!(clients.for_node("https://node.example.com").is_ok());
    }

    #[tokio::test]
    async fn test_resolver_refuses_private_names() {
        assert!(PublicOnly.resolve(Name::from_str("localhost").unwrap()).await.is_err());
    }

    #[tokio::test]
    async fn test_public_client_refuses_localhost() {
        let clients = NodeClients::new(&[]).unwrap();
        let client = clients.for_node("http://localhost:9").unwrap();
        let err = client.get("http://localhost:9/shard/x").send().await.unwrap_err();
        assert!(format!("{:?}", err).contains("not a public address"), "{:?}", err);
    }
}
