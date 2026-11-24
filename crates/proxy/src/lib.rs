//! Fiddler-lite: explicit HTTP proxy + CONNECT tunnel.
//!
//! v1: forwards requests and logs metadata (method, target, byte counts).
//! TLS content inspection (CA + rcgen) is a later layer on top of CONNECT.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::sync::{Semaphore, mpsc};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const TUNNEL_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad request line: {0}")]
    BadRequest(String),
    #[error("target blocked by policy: {0}")]
    Blocked(String),
}

/// Runtime limits and SSRF policy for [`serve_with_config`].
#[derive(Debug, Clone, Copy)]
pub struct ProxyConfig {
    /// Maximum concurrent client connections.
    pub max_conns: usize,
    /// Allow forwarding to loopback / link-local / unspecified targets.
    /// Defaults to `false` to prevent SSRF against localhost services.
    pub allow_local: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            max_conns: 256,
            allow_local: false,
        }
    }
}

/// One proxied connection, logged when it closes.
#[derive(Debug, Clone, Serialize)]
pub struct ProxyEvent {
    pub client: String,
    pub method: String,
    pub target: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

/// Serve the proxy on `addr` with default limits and SSRF protection;
/// closed-connection events go to `events` (non-blocking `try_send`).
pub async fn serve(addr: SocketAddr, events: mpsc::Sender<ProxyEvent>) -> Result<(), Error> {
    serve_with_config(addr, events, ProxyConfig::default()).await
}

/// Serve the proxy on `addr` with explicit [`ProxyConfig`].
pub async fn serve_with_config(
    addr: SocketAddr,
    events: mpsc::Sender<ProxyEvent>,
    cfg: ProxyConfig,
) -> Result<(), Error> {
    let listener = TcpListener::bind(addr).await?;
    let permits = Arc::new(Semaphore::new(cfg.max_conns.max(1)));
    loop {
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::Io(std::io::Error::other("semaphore closed")))?;
        let (client, peer) = listener.accept().await?;
        let events = events.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = handle(client, peer, events, cfg).await;
        });
    }
}

async fn handle(
    mut client: TcpStream,
    peer: SocketAddr,
    events: mpsc::Sender<ProxyEvent>,
    cfg: ProxyConfig,
) -> Result<(), Error> {
    // Read the request header block (bounded), scanning only newly arrived bytes.
    let mut buf = Vec::with_capacity(4096);
    buf.resize(16 * 1024, 0);
    let mut used = 0usize;
    let header_end = loop {
        let n = tokio::time::timeout(HEADER_TIMEOUT, client.read(&mut buf[used..]))
            .await
            .map_err(|_| Error::BadRequest("header timeout".into()))??;
        if n == 0 {
            return Err(Error::BadRequest("client closed".into()));
        }
        let scan_start = used.saturating_sub(3);
        used += n;
        if let Some(rel) = find_header_end(&buf[scan_start..used]) {
            break scan_start + rel;
        }
        if used == buf.len() {
            return Err(Error::BadRequest("headers too large".into()));
        }
    };

    let head = String::from_utf8_lossy(&buf[..header_end]);
    let request_line = head.lines().next().unwrap_or_default().to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let uri = parts.next().unwrap_or_default().to_string();

    let target =
        request_target(&method, &uri).ok_or_else(|| Error::BadRequest(request_line.clone()))?;
    let upstream_addr = resolve_target(&target, cfg.allow_local).await?;

    let mut upstream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(upstream_addr))
        .await
        .map_err(|_| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect timeout",
            ))
        })??;

    if method == "CONNECT" {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    } else {
        upstream.write_all(&buf[..used]).await?;
    }

    // Dumb tunnel from here — covers keep-alive and CONNECT alike.
    let (up, down) = tokio::time::timeout(
        TUNNEL_TIMEOUT,
        tokio::io::copy_bidirectional(&mut client, &mut upstream),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .unwrap_or((0, 0));

    let _ = events.try_send(ProxyEvent {
        client: peer.ip().to_string(),
        method,
        target,
        bytes_up: up,
        bytes_down: down,
    });
    Ok(())
}

fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unicast_link_local() || v6.is_unspecified(),
    }
}

async fn resolve_target(target: &str, allow_local: bool) -> Result<SocketAddr, Error> {
    let mut addrs = tokio::time::timeout(CONNECT_TIMEOUT, lookup_host(target))
        .await
        .map_err(|_| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "dns timeout",
            ))
        })??;
    let first = addrs
        .next()
        .ok_or_else(|| Error::BadRequest(format!("unresolved target: {target}")))?;
    if !allow_local && is_blocked_ip(first.ip()) {
        return Err(Error::Blocked(target.to_string()));
    }
    Ok(first)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// `host:port` the request should be forwarded to.
fn request_target(method: &str, uri: &str) -> Option<String> {
    if method == "CONNECT" {
        return (!uri.is_empty()).then(|| uri.to_string());
    }
    let (rest, default_port) = if let Some(r) = uri.strip_prefix("http://") {
        (r, 80)
    } else {
        (uri.strip_prefix("https://")?, 443)
    };
    let authority = rest.split('/').next()?;
    if authority.is_empty() {
        return None;
    }
    // Handle bracketed IPv6 literals like `[::1]` vs `[::1]:8080`.
    if let Some(after_bracket) = authority.strip_prefix('[') {
        let (_, tail) = after_bracket.split_once(']')?;
        if tail.starts_with(':') {
            Some(authority.to_string())
        } else if tail.is_empty() {
            Some(format!("{authority}:{default_port}"))
        } else {
            None
        }
    } else if authority.contains(':') {
        Some(authority.to_string())
    } else {
        Some(format!("{authority}:{default_port}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_end_found() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(18));
        assert_eq!(find_header_end(b"GET /\r\n"), None);
    }

    #[test]
    fn targets() {
        assert_eq!(
            request_target("CONNECT", "example.com:443").as_deref(),
            Some("example.com:443")
        );
        assert_eq!(
            request_target("GET", "http://h.test/path?q=1").as_deref(),
            Some("h.test:80")
        );
        assert_eq!(
            request_target("GET", "http://h.test:8080/x").as_deref(),
            Some("h.test:8080")
        );
        assert_eq!(
            request_target("GET", "http://[::1]/x").as_deref(),
            Some("[::1]:80")
        );
        assert_eq!(
            request_target("GET", "http://[::1]:8080/x").as_deref(),
            Some("[::1]:8080")
        );
        assert_eq!(request_target("GET", "/relative/path"), None);
    }

    #[test]
    fn blocks_loopback_and_link_local_by_default() {
        assert!(is_blocked_ip("127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("169.254.169.254".parse().unwrap()));
        assert!(is_blocked_ip("::1".parse().unwrap()));
        assert!(!is_blocked_ip("93.184.216.34".parse().unwrap()));
    }
}
