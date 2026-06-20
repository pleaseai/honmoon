//! HTTP CONNECT egress gateway (Phase 1).
//!
//! Agents point `https_proxy` at this proxy. The client issues
//! `CONNECT host:port`; we evaluate the target host against the [`Policy`] and
//! either reject with `403` or open a raw TCP tunnel to the target.
//!
//! This is a *terminating* CONNECT forward proxy implemented directly on tokio.
//! Deeper HTTP request inspection (TLS termination, method/path/body rules) is a
//! later phase and is where a framework like Pingora earns its keep — see
//! [ADR-0002]. For host-level egress filtering, raw tunneling is simpler and correct.
//!
//! [ADR-0002]: ../../../.please/docs/decisions/0002-phase1-connect-proxy-on-tokio.md

use std::time::Duration;

use honmoon_core::{Facts, Policy, Verdict};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::evaluate;

const MAX_REQUEST_HEAD: usize = 8 * 1024;
/// Max time to receive the CONNECT request head before giving up (slowloris guard).
const HEAD_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Bind `addr` and run the egress proxy, blocking forever (until process exit).
pub fn run(policy: Policy, addr: &str) -> ! {
    let listener = std::net::TcpListener::bind(addr).unwrap_or_else(|e| panic!("bind {addr}: {e}"));
    serve_listener(policy, listener)
}

/// Run the egress proxy on an already-bound listener, blocking forever.
///
/// Taking a pre-bound listener lets `honmoon run` hand off a socket it bound
/// itself — no free-port-then-rebind window (no TOCTOU race).
pub fn serve_listener(policy: Policy, listener: std::net::TcpListener) -> ! {
    listener
        .set_nonblocking(true)
        .expect("set listener non-blocking");
    let runtime = tokio::runtime::Runtime::new().expect("build tokio runtime");
    runtime.block_on(serve(policy, listener))
}

async fn serve(policy: Policy, std_listener: std::net::TcpListener) -> ! {
    let listener = TcpListener::from_std(std_listener).expect("adopt std listener");
    let addr = listener.local_addr().expect("listener addr");
    tracing::info!(%addr, "egress proxy listening");
    let policy = std::sync::Arc::new(policy);
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let policy = policy.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(stream, &policy).await {
                        tracing::debug!(%peer, error = %e, "connection ended");
                    }
                });
            }
            Err(e) => tracing::warn!(error = %e, "accept failed"),
        }
    }
}

/// Handle one client connection: parse the CONNECT request, apply policy, tunnel.
async fn handle(mut client: TcpStream, policy: &Policy) -> std::io::Result<()> {
    let head = match tokio::time::timeout(HEAD_READ_TIMEOUT, read_head(&mut client)).await {
        Ok(result) => result?,
        Err(_elapsed) => return respond(&mut client, 408, "Request Timeout").await,
    };
    let Some((method, target)) = parse_request_line(&head) else {
        return respond(&mut client, 400, "Bad Request").await;
    };

    if method != "CONNECT" {
        // Phase 1 only supports HTTPS egress via CONNECT tunneling.
        return respond(&mut client, 405, "Method Not Allowed").await;
    }

    let host = canonical_host(&target);
    let facts = Facts {
        domain: Some(host.clone()),
    };
    if evaluate(policy, &facts) != Verdict::Allow {
        tracing::info!(domain = %host, "egress blocked");
        return respond(&mut client, 403, "Forbidden").await;
    }

    let mut upstream = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(%target, error = %e, "upstream connect failed");
            return respond(&mut client, 502, "Bad Gateway").await;
        }
    };

    tracing::debug!(domain = %host, %target, "egress allowed, tunneling");
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Read the request head (up to the blank line) without consuming tunnel bytes.
async fn read_head(client: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = client.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > MAX_REQUEST_HEAD {
            break;
        }
    }
    Ok(buf)
}

/// Parse `METHOD TARGET VERSION` from the first request line.
fn parse_request_line(head: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(head).ok()?;
    let line = text.lines().next()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    Some((method, target))
}

/// Extract the host from a CONNECT `host:port` authority (handles IPv6 `[::1]:443`).
fn host_of(target: &str) -> &str {
    if let Some(rest) = target.strip_prefix('[') {
        // IPv6 literal: [addr]:port
        return rest.split(']').next().unwrap_or(rest);
    }
    target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target)
}

/// Canonicalize the CONNECT host for policy evaluation: strip the port, drop a
/// trailing dot (FQDN root), and lowercase. Without this, `GitHub.com` or
/// `github.com.` could bypass a `github.com` rule.
fn canonical_host(target: &str) -> String {
    host_of(target).trim_end_matches('.').to_ascii_lowercase()
}

async fn respond(client: &mut TcpStream, status: u16, reason: &str) -> std::io::Result<()> {
    let msg =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    client.write_all(msg.as_bytes()).await?;
    client.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_line() {
        let (m, t) = parse_request_line(b"CONNECT github.com:443 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(m, "CONNECT");
        assert_eq!(t, "github.com:443");
    }

    #[test]
    fn host_of_strips_port() {
        assert_eq!(host_of("github.com:443"), "github.com");
        assert_eq!(host_of("[::1]:443"), "::1");
        assert_eq!(host_of("nohost"), "nohost");
    }

    #[test]
    fn canonical_host_lowercases_and_trims_dot() {
        assert_eq!(canonical_host("GitHub.com:443"), "github.com");
        assert_eq!(canonical_host("github.com.:443"), "github.com");
        assert_eq!(canonical_host("API.Example.COM:8443"), "api.example.com");
    }
}
