//! SOCKS5 listener (RFC 1928) — the transport for non-HTTP protocols.
//!
//! The CONNECT proxy in [`crate::gateway`] only carries HTTP and TLS. A
//! PostgreSQL or Redis client speaks neither, so [ADR-0005] §3 adds a SOCKS5
//! listener beside it: the handshake states the destination `host:port` in the
//! clear, which is exactly what [`Policy::endpoint_for`] needs to select an
//! endpoint and its protocol runtime — no destination-IP index, no DNS
//! interception, no virtual-IP allocation.
//!
//! Every connection is first gated exactly like a CONNECT — `Facts { domain,
//! endpoint }` → [`decide_explained`], then allow / deny / hold for approval —
//! so the egress lists and their default mean the same thing on every path, for
//! every protocol. Only then is it dispatched:
//!
//! 1. The destination resolves to an endpoint declared `protocol: postgres` —
//!    the connection is handed to [`crate::runtime::postgres`], which parses
//!    every query frame and applies policy again, per statement.
//! 2. It resolves to one declared `protocol: kubernetes` — **refused**. Those
//!    facts come from decrypting HTTPS, which only the CONNECT proxy does, so a
//!    tunnel here would carry API calls no `k8s.*` rule could ever see. This is
//!    the mirror of [`crate::mitm`] refusing a `postgres` endpoint over CONNECT.
//! 3. Anything else (no endpoint, or `tcp`) — a generic TCP tunnel.
//!
//! Only no-auth (`0x00`) and `CONNECT` are supported; the listener is meant to
//! be bound to loopback for a local agent, so there is no client to
//! authenticate. The success reply is sent **after** the upstream TCP connect
//! succeeds, so a client never sees a tunnel that does not exist.
//!
//! [ADR-0005]: ../../../.please/docs/decisions/0005-empty-namespace-and-bridged-proxy-sockets.md

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use honmoon_core::{
    AuditDraft, Decision, EndpointProtocol, Facts, FactsSummary, Verdict, decide_explained,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::approval::{HoldOutcome, hold};
use crate::gateway::GatewayState;
use crate::runtime::postgres;

/// The only protocol version RFC 1928 defines.
const VERSION: u8 = 0x05;
/// "No authentication required" — the only method offered.
const METHOD_NO_AUTH: u8 = 0x00;
/// "No acceptable methods" — sent when the client offers no-auth nowhere.
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
/// The only command served; `BIND`/`UDP ASSOCIATE` are refused.
const CMD_CONNECT: u8 = 0x01;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Reply codes (RFC 1928 §6).
const REPLY_SUCCESS: u8 = 0x00;
const REPLY_GENERAL_FAILURE: u8 = 0x01;
/// Refused by policy — the verdict a `deny` rule produces.
const REPLY_NOT_ALLOWED: u8 = 0x02;
/// Upstream TCP connect failed.
const REPLY_CONNECTION_REFUSED: u8 = 0x05;
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REPLY_ADDRESS_NOT_SUPPORTED: u8 = 0x08;

/// Backstop on the greeting's method list, so a malformed client cannot make us
/// wait on bytes that never come.
const MAX_METHODS: usize = 255;

/// How long a client has to finish the handshake (greeting + CONNECT request).
/// The listener takes no credentials, so without a deadline a peer that opens a
/// socket and then says nothing pins a task and a file descriptor forever. Only
/// the handshake is bounded — an established tunnel or a PostgreSQL session is
/// long-lived by design and is never timed out.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the upstream TCP connect may take before it is given up on. A
/// destination that silently drops SYNs would otherwise hold the handler until
/// the kernel gives up minutes later, and every handler holds one of the
/// [`MAX_CONCURRENT_CONNECTIONS`] permits for its whole life — so that many
/// requests to such a host take the listener out of service without sending a
/// single byte of payload. Only the connect is bounded; the tunnel it opens is
/// long-lived by design.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Ceiling on SOCKS5 connections in flight at once, each holding a permit for
/// its whole life. A connection over the cap is **dropped**, not queued: queuing
/// on an unauthenticated listener only moves the exhaustion from file
/// descriptors to memory, and a refused client is free to retry.
const MAX_CONCURRENT_CONNECTIONS: usize = 512;

/// The destination a client asked for, as it declared it: a domain stays a
/// domain (canonicalized like a CONNECT authority), an IP literal is formatted
/// back to text. Policy matches on this, never on a resolved address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub host: String,
    pub port: u16,
}

/// Bind `listener` and serve SOCKS5 forever (until process exit).
///
/// Mirrors [`crate::gateway::serve`]: takes an already-bound `std` listener so
/// the caller can bind before spawning (no free-port-then-rebind race).
pub async fn serve_socks(state: GatewayState, std_listener: std::net::TcpListener) -> ! {
    std_listener
        .set_nonblocking(true)
        .expect("set SOCKS listener non-blocking");
    let listener = TcpListener::from_std(std_listener).expect("adopt std listener");
    let addr = listener.local_addr().expect("listener addr");
    tracing::info!(%addr, "SOCKS5 listener listening");

    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    loop {
        let (client, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "SOCKS5 accept failed");
                continue;
            }
        };
        // At the cap, dropping `client` here closes it immediately — the accept
        // loop keeps running rather than piling connections up behind itself.
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            tracing::debug!(%peer, "SOCKS5 connection cap reached; dropping connection");
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_connection(state, client).await {
                tracing::debug!(%peer, error = %e, "SOCKS5 connection ended");
            }
        });
    }
}

/// Greet, read the CONNECT request, then dispatch to a protocol runtime or a
/// gated raw tunnel.
async fn handle_connection(state: GatewayState, mut client: TcpStream) -> std::io::Result<()> {
    // Only the handshake is deadlined; what it dispatches to is not.
    let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        if !negotiate(&mut client).await? {
            return Ok(None);
        }
        read_request(&mut client).await.map(Some)
    })
    .await;
    let Ok(handshake) = handshake else {
        tracing::debug!("SOCKS5 handshake timed out; dropping connection");
        return Ok(());
    };

    let target = match handshake? {
        None => return Ok(()),
        Some(Ok(target)) => target,
        Some(Err(code)) => {
            reply(&mut client, code, None).await?;
            return Ok(());
        }
    };

    // Resolve the endpoint once, owned, so the policy borrow ends here.
    let endpoint = state
        .policy
        .endpoint_for(&target.host, target.port)
        .map(|(name, endpoint)| (name.to_owned(), endpoint.protocol));
    let name = endpoint.as_ref().map(|(name, _)| name.clone());

    // Before the gate, so no `Allowed` entry and no approval hold is created for
    // a connection that is going to be refused anyway.
    if let Some((name, EndpointProtocol::Kubernetes)) = &endpoint {
        refuse_uninspectable_socks(&state, &target, name);
        return reply(&mut client, REPLY_NOT_ALLOWED, None).await;
    }

    // Gate the connection before dispatching, so a protocol runtime never
    // becomes a way around the egress default.
    if !connection_gate(&state, &target, name).await {
        return reply(&mut client, REPLY_NOT_ALLOWED, None).await;
    }

    // Every protocol is named: a variant added later fails to compile here
    // rather than falling into a tunnel honmoon cannot inspect.
    match endpoint {
        Some((name, EndpointProtocol::Postgres)) => {
            run_postgres_endpoint(&state, client, target, name).await
        }
        // Refused above. Answered the same way rather than tunnelled if it is
        // ever reached, so the fail-closed answer does not depend on one
        // `if let` staying where it is.
        Some((_, EndpointProtocol::Kubernetes)) => {
            reply(&mut client, REPLY_NOT_ALLOWED, None).await
        }
        Some((_, EndpointProtocol::Tcp)) | None => tunnel(client, target).await,
    }
}

/// Read the client greeting and answer with the chosen method. Returns whether
/// the connection may proceed (no-auth was offered).
async fn negotiate(client: &mut TcpStream) -> std::io::Result<bool> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Ok(false);
    }
    let count = usize::from(head[1]).min(MAX_METHODS);
    let mut methods = vec![0u8; count];
    client.read_exact(&mut methods).await?;

    if !methods.contains(&METHOD_NO_AUTH) {
        client.write_all(&[VERSION, METHOD_NONE_ACCEPTABLE]).await?;
        return Ok(false);
    }
    client.write_all(&[VERSION, METHOD_NO_AUTH]).await?;
    Ok(true)
}

/// Read one SOCKS5 request off the wire. The outer error is an I/O failure (the
/// connection is simply dropped); the inner `Err(code)` is a reply to send back.
async fn read_request(client: &mut TcpStream) -> std::io::Result<Result<Target, u8>> {
    let mut head = [0u8; 4];
    client.read_exact(&mut head).await?;
    let mut request = head.to_vec();

    // Read exactly the declared address length so the request buffer handed to
    // `parse_request` is complete and self-describing.
    let address_len = match head[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            request.push(len[0]);
            usize::from(len[0])
        }
        // An unknown address type leaves the rest of the request unframed, so
        // there is nothing to drain — answer and close.
        _ => return Ok(Err(REPLY_ADDRESS_NOT_SUPPORTED)),
    };

    let mut rest = vec![0u8; address_len + 2];
    client.read_exact(&mut rest).await?;
    request.extend_from_slice(&rest);
    Ok(parse_request(&request))
}

/// Parse a complete SOCKS5 request into its destination, or the reply code that
/// refuses it. Pure over the request bytes so it can be unit-tested.
pub(crate) fn parse_request(request: &[u8]) -> Result<Target, u8> {
    if request.len() < 4 || request[0] != VERSION {
        return Err(REPLY_GENERAL_FAILURE);
    }
    // RFC 1928 §4: RSV is reserved and must be zero. A client that sets it is
    // not speaking the protocol honmoon parses.
    if request[2] != 0x00 {
        return Err(REPLY_GENERAL_FAILURE);
    }
    if request[1] != CMD_CONNECT {
        // BIND and UDP ASSOCIATE: honmoon inspects streams it proxies, and
        // neither carries a destination it could gate on the handshake.
        return Err(REPLY_COMMAND_NOT_SUPPORTED);
    }

    let (host, rest) = match request[3] {
        ATYP_IPV4 => {
            let octets: [u8; 4] = request
                .get(4..8)
                .and_then(|s| s.try_into().ok())
                .ok_or(REPLY_GENERAL_FAILURE)?;
            (Ipv4Addr::from(octets).to_string(), &request[8..])
        }
        ATYP_IPV6 => {
            let octets: [u8; 16] = request
                .get(4..20)
                .and_then(|s| s.try_into().ok())
                .ok_or(REPLY_GENERAL_FAILURE)?;
            (Ipv6Addr::from(octets).to_string(), &request[20..])
        }
        ATYP_DOMAIN => {
            let len = usize::from(*request.get(4).ok_or(REPLY_GENERAL_FAILURE)?);
            let end = 5 + len;
            let bytes = request.get(5..end).ok_or(REPLY_GENERAL_FAILURE)?;
            let name = std::str::from_utf8(bytes).map_err(|_| REPLY_ADDRESS_NOT_SUPPORTED)?;
            // Canonicalized like a CONNECT authority, so `Example.COM.` cannot
            // slip past a rule written for `example.com`.
            (
                name.trim_end_matches('.').to_ascii_lowercase(),
                &request[end..],
            )
        }
        _ => return Err(REPLY_ADDRESS_NOT_SUPPORTED),
    };

    let port: [u8; 2] = rest
        .get(..2)
        .and_then(|s| s.try_into().ok())
        .ok_or(REPLY_GENERAL_FAILURE)?;
    Ok(Target {
        host,
        port: u16::from_be_bytes(port),
    })
}

/// Send a SOCKS5 reply. `bound` is the local address of the upstream socket on
/// success; failures report the unspecified address, as RFC 1928 allows.
async fn reply(client: &mut TcpStream, code: u8, bound: Option<SocketAddr>) -> std::io::Result<()> {
    client.write_all(&reply_bytes(code, bound)).await
}

/// Encode a SOCKS5 reply: `VER REP RSV ATYP BND.ADDR BND.PORT`.
fn reply_bytes(code: u8, bound: Option<SocketAddr>) -> Vec<u8> {
    let mut out = vec![VERSION, code, 0x00];
    match bound {
        Some(SocketAddr::V6(addr)) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        Some(SocketAddr::V4(addr)) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        None => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        }
    }
    out
}

/// Apply connection-level policy to the destination the client asked for.
/// Returns whether the connection may proceed; a refusal is the caller's `0x02`.
///
/// This is the SOCKS5 equivalent of [`crate::mitm`]'s CONNECT host gate, and it
/// runs for **every** destination — a declared `postgres` endpoint included.
/// A protocol runtime decides the statements a connection carries, not whether
/// the connection is permitted at all: without this gate `egress.default: deny`
/// would block a `kubernetes` endpoint over HTTPS while silently admitting a
/// `postgres` one, and a firewall must not have a protocol that ignores its own
/// default.
///
/// Statement rules do not fire here: a condition over `sql.*` cannot match facts
/// that have no statement yet, and an unknown fact reference never matches (the
/// engine fails closed on it). So a policy that only names `sql.*` conditions
/// for an endpoint still falls through to the egress lists at connect time.
async fn connection_gate(state: &GatewayState, target: &Target, endpoint: Option<String>) -> bool {
    let facts = Facts {
        domain: Some(target.host.clone()),
        endpoint,
        ..Default::default()
    };
    let outcome = decide_explained(&state.policy, &facts);
    let summary = FactsSummary::from(&facts);

    match outcome.verdict {
        Verdict::Allow => {
            // One entry per accepted connection, matching the CONNECT gate
            // (`host_gate(.., audit_allow = true)` in [`crate::mitm`]) so both
            // paths log the same thing. It is per connection, not per tunnelled
            // byte, so the bounded ring is not flooded.
            state.audit.record(AuditDraft {
                decision: Decision::Allowed,
                verdict: Verdict::Allow,
                rule: outcome.rule,
                facts: summary,
                approval_id: None,
            });
            true
        }
        Verdict::Deny => {
            tracing::info!(domain = %target.host, rule = ?outcome.rule, "SOCKS5 egress denied");
            state.audit.record(AuditDraft {
                decision: Decision::Denied,
                verdict: Verdict::Deny,
                rule: outcome.rule,
                facts: summary,
                approval_id: None,
            });
            false
        }
        Verdict::Pause => {
            let approval = connect_summary(target, outcome.rule.as_deref());
            matches!(
                hold(state, &target.host, summary, outcome.rule, approval).await,
                HoldOutcome::Approved
            )
        }
    }
}

/// Refuse a SOCKS5 connection to an endpoint whose facts only exist behind TLS
/// termination, without ever opening a tunnel honmoon could not inspect.
///
/// A `kubernetes` endpoint is inspected by decrypting HTTPS and reading the
/// request line — [`crate::mitm`]'s job. SOCKS5 terminates nothing, so a tunnel
/// here would carry `DELETE /api/v1/namespaces/prod/secrets/x` straight past a
/// `k8s.resource == 'secrets'` deny rule, which would never see a fact. This is
/// the mirror of [`crate::mitm`] refusing a `postgres` endpoint over CONNECT,
/// and it keeps the same audit semantics:
///
/// - `deny` is answered exactly as anywhere else — the connection was refused
///   on its own merits and the transport is beside the point.
/// - `allow` becomes the transport refusal. No `Allowed` entry is recorded for
///   a connection that never happens.
/// - `pause` is refused too, and is **not** held: a human cannot approve a
///   transport into inspecting requests it never sees, so the queue would only
///   offer an approval that cannot mean what it says. The rule that paused it is
///   still what the audit entry names.
///
/// The audit entry keeps `decision` and `verdict` apart: the disposition is a
/// denial (honmoon refused the connection) while the verdict stays whatever the
/// policy actually said, so the entry never claims a rule denied something it
/// allowed.
fn refuse_uninspectable_socks(state: &GatewayState, target: &Target, endpoint: &str) {
    let facts = Facts {
        domain: Some(target.host.clone()),
        endpoint: Some(endpoint.to_owned()),
        ..Default::default()
    };
    let outcome = decide_explained(&state.policy, &facts);
    let summary = FactsSummary::from(&facts);

    if outcome.verdict == Verdict::Deny {
        tracing::info!(domain = %target.host, rule = ?outcome.rule, "SOCKS5 egress denied");
        state.audit.record(AuditDraft {
            decision: Decision::Denied,
            verdict: Verdict::Deny,
            rule: outcome.rule,
            facts: summary,
            approval_id: None,
        });
        return;
    }

    tracing::info!(
        domain = %target.host,
        %endpoint,
        rule = ?outcome.rule,
        verdict = ?outcome.verdict,
        "SOCKS5 connection to a TLS-inspected endpoint refused"
    );
    state.audit.record(AuditDraft {
        decision: Decision::Denied,
        verdict: outcome.verdict,
        // Whatever matched, named — an operator reading the entry needs to see
        // the rule that was in play, not a bare synthetic denial.
        rule: outcome.rule,
        facts: summary,
        approval_id: None,
    });
}

/// Hand an already-gated connection to the PostgreSQL runtime, which decides
/// every statement it carries.
async fn run_postgres_endpoint(
    state: &GatewayState,
    mut client: TcpStream,
    target: Target,
    endpoint: String,
) -> std::io::Result<()> {
    let upstream = match connect_upstream(&mut client, &target).await? {
        Some(upstream) => upstream,
        None => return Ok(()),
    };
    reply(&mut client, REPLY_SUCCESS, upstream.local_addr().ok()).await?;

    let facts = Facts {
        domain: Some(target.host.clone()),
        endpoint: Some(endpoint),
        ..Default::default()
    };
    postgres::run_postgres(state, client, upstream, facts).await
}

/// Splice an already-gated connection to its destination, raw.
async fn tunnel(mut client: TcpStream, target: Target) -> std::io::Result<()> {
    let mut upstream = match connect_upstream(&mut client, &target).await? {
        Some(upstream) => upstream,
        None => return Ok(()),
    };
    reply(&mut client, REPLY_SUCCESS, upstream.local_addr().ok()).await?;
    copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Dial the destination, giving up after [`CONNECT_TIMEOUT`]. On failure — or
/// on that deadline — the client is answered `0x05` and `None` is returned; the
/// success reply is only ever sent over a live upstream socket.
async fn connect_upstream(
    client: &mut TcpStream,
    target: &Target,
) -> std::io::Result<Option<TcpStream>> {
    let connect = TcpStream::connect((target.host.as_str(), target.port));
    let outcome = match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
        Ok(outcome) => outcome,
        // A host that drops SYNs never fails, it just never answers. Report it
        // to the client the same way a refused connect is reported: either way
        // honmoon has no upstream socket to hand over.
        Err(elapsed) => {
            tracing::info!(host = %target.host, port = target.port, error = %elapsed, "SOCKS5 upstream connect timed out");
            reply(client, REPLY_CONNECTION_REFUSED, None).await?;
            return Ok(None);
        }
    };
    match outcome {
        Ok(upstream) => Ok(Some(upstream)),
        Err(e) => {
            tracing::info!(host = %target.host, port = target.port, error = %e, "SOCKS5 upstream connect failed");
            reply(client, REPLY_CONNECTION_REFUSED, None).await?;
            Ok(None)
        }
    }
}

/// A short human description of a held tunnel, for the approval queue.
fn connect_summary(target: &Target, rule: Option<&str>) -> String {
    let Target { host, port } = target;
    match rule {
        Some(r) => format!("SOCKS5 {host}:{port} (rule: {r})"),
        None => format!("SOCKS5 {host}:{port}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(atyp: u8, address: &[u8], port: u16) -> Vec<u8> {
        let mut out = vec![VERSION, CMD_CONNECT, 0x00, atyp];
        out.extend_from_slice(address);
        out.extend_from_slice(&port.to_be_bytes());
        out
    }

    #[test]
    fn parses_the_three_address_types() {
        assert_eq!(
            parse_request(&request(ATYP_IPV4, &[127, 0, 0, 1], 5432)),
            Ok(Target {
                host: "127.0.0.1".into(),
                port: 5432
            })
        );

        let mut domain = vec![11u8];
        domain.extend_from_slice(b"DB.Internal");
        assert_eq!(
            parse_request(&request(ATYP_DOMAIN, &domain, 5432)),
            Ok(Target {
                host: "db.internal".into(),
                port: 5432
            }),
            "a domain is canonicalized like a CONNECT authority"
        );

        let loopback = Ipv6Addr::LOCALHOST.octets();
        assert_eq!(
            parse_request(&request(ATYP_IPV6, &loopback, 6379)),
            Ok(Target {
                host: "::1".into(),
                port: 6379
            })
        );
    }

    #[test]
    fn refuses_non_connect_commands_and_unknown_address_types() {
        let mut bind = request(ATYP_IPV4, &[127, 0, 0, 1], 5432);
        bind[1] = 0x02; // BIND
        assert_eq!(parse_request(&bind), Err(REPLY_COMMAND_NOT_SUPPORTED));

        let mut unknown = request(ATYP_IPV4, &[127, 0, 0, 1], 5432);
        unknown[3] = 0x09;
        assert_eq!(parse_request(&unknown), Err(REPLY_ADDRESS_NOT_SUPPORTED));
    }

    #[test]
    fn refuses_a_non_zero_reserved_byte() {
        let mut reserved = request(ATYP_IPV4, &[127, 0, 0, 1], 5432);
        reserved[2] = 0x01;
        assert_eq!(
            parse_request(&reserved),
            Err(REPLY_GENERAL_FAILURE),
            "RFC 1928 reserves RSV as zero"
        );
    }

    #[test]
    fn refuses_truncated_requests() {
        assert_eq!(
            parse_request(&[VERSION, CMD_CONNECT]),
            Err(REPLY_GENERAL_FAILURE)
        );
        // Address present but the port was cut off.
        assert_eq!(
            parse_request(&[VERSION, CMD_CONNECT, 0x00, ATYP_IPV4, 127, 0, 0, 1]),
            Err(REPLY_GENERAL_FAILURE)
        );
    }

    #[test]
    fn reply_bytes_report_the_bound_address() {
        let bound: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        assert_eq!(
            reply_bytes(REPLY_SUCCESS, Some(bound)),
            vec![
                VERSION,
                REPLY_SUCCESS,
                0,
                ATYP_IPV4,
                127,
                0,
                0,
                1,
                0x04,
                0xD2
            ]
        );
        assert_eq!(
            reply_bytes(REPLY_NOT_ALLOWED, None),
            vec![VERSION, REPLY_NOT_ALLOWED, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]
        );
    }
}
