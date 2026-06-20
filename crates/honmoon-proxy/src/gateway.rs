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

use std::net::SocketAddr;

use honmoon_core::{Facts, Policy, Verdict};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::evaluate;

const MAX_REQUEST_HEAD: usize = 8 * 1024;

/// Run the egress proxy, blocking forever (until process exit).
pub fn run(policy: Policy, addr: &str) -> ! {
    let runtime = tokio::runtime::Runtime::new().expect("build tokio runtime");
    let addr: SocketAddr = addr.parse().expect("valid listen address");
    runtime.block_on(serve(policy, addr))
}

async fn serve(policy: Policy, addr: SocketAddr) -> ! {
    let listener = TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("bind {addr}: {e}"));
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
    let head = read_head(&mut client).await?;
    let Some((method, target)) = parse_request_line(&head) else {
        return respond(&mut client, 400, "Bad Request").await;
    };

    if method != "CONNECT" {
        // Phase 1 only supports HTTPS egress via CONNECT tunneling.
        return respond(&mut client, 405, "Method Not Allowed").await;
    }

    let host = host_of(&target);
    let facts = Facts {
        domain: Some(host.to_string()),
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
}
