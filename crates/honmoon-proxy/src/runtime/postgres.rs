//! Inline PostgreSQL protocol runtime (see [ADR-0007]).
//!
//! Sits between a client that dialed a `protocol: postgres` endpoint through
//! the SOCKS5 listener and the real database. Every frame the client sends is
//! framed; `Q` (simple query) and `P` (Parse, extended protocol) carry SQL, so
//! their statement is parsed into [`SqlFacts`](honmoon_core::SqlFacts) and
//! decided by the policy engine before a byte reaches the database. Everything
//! else is streamed through untouched, and the upstream→client direction is a
//! raw copy.
//!
//! Inspection needs plaintext between the client and honmoon, so `SSLRequest`
//! and `GSSENCRequest` are answered `N` — the client then falls back to
//! plaintext (`sslmode=prefer`) or fails (`sslmode=require`). The upstream leg
//! is plaintext in v0.1.0.
//!
//! A refused statement is answered with an `ErrorResponse` (SQLSTATE `42501`,
//! insufficient privilege) followed by `ReadyForQuery`, so the client sees a
//! normal permission error and the session stays usable — closing the socket
//! would surface as an unexplained connection reset.
//!
//! [ADR-0007]: ../../../../.please/docs/decisions/0007-inline-postgresql-runtime-semantics.md

use std::sync::Arc;

use honmoon_core::{
    AuditDraft, Decision, Facts, FactsSummary, SqlFacts, Verdict, decide_explained,
    protocols::{parse_postgres_query, parse_sql},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::approval::{HoldOutcome, hold};
use crate::gateway::GatewayState;

/// Largest `Q`/`P` frame honmoon will buffer to inspect. A larger one is
/// **denied**, not forwarded: unlike an over-cap HTTP body (which is forwarded
/// un-inspected), a query padded past the cap would otherwise be a one-line
/// bypass for a `DROP` rule. See ADR-0007.
pub const MAX_PG_FRAME: usize = 1024 * 1024;

/// Startup packet codes sent in place of a protocol version.
const SSL_REQUEST: u32 = 80_877_103;
const GSSENC_REQUEST: u32 = 80_877_104;
const CANCEL_REQUEST: u32 = 80_877_102;
/// Protocol version 3.0, the version every supported client speaks.
const PROTOCOL_V3: u32 = 196_608;

/// `ReadyForQuery` with transaction status `I` (idle) — sent after every refusal
/// so the client knows the extended-protocol pipeline is drained.
const READY_FOR_QUERY: [u8; 6] = [b'Z', 0, 0, 0, 5, b'I'];

/// SQLSTATE 42501 — insufficient privilege. The closest standard code to "a
/// policy refused this", and one every driver already surfaces sensibly.
const SQLSTATE_INSUFFICIENT_PRIVILEGE: &str = "42501";

/// Copy buffer for the pass-through paths.
const COPY_CHUNK: usize = 16 * 1024;

/// A client writer shared between the refusal path and the upstream→client copy
/// task, so an injected `ErrorResponse` can never interleave with a server frame.
type ClientWriter = Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>;

/// Run the PostgreSQL runtime over an established client/upstream pair.
///
/// The SOCKS5 layer has already answered the client's handshake, so both halves
/// are ready to carry protocol bytes. Returns when either side closes.
pub async fn run_postgres(
    state: &GatewayState,
    client: TcpStream,
    upstream: TcpStream,
    facts: Facts,
) -> std::io::Result<()> {
    let (mut client_read, client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();
    let client_write: ClientWriter = Arc::new(Mutex::new(client_write));

    let mut downstream = tokio::spawn({
        let client_write = Arc::clone(&client_write);
        async move {
            let mut buf = vec![0u8; COPY_CHUNK];
            loop {
                let read = match upstream_read.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let mut writer = client_write.lock().await;
                if writer.write_all(&buf[..read]).await.is_err() {
                    break;
                }
            }
        }
    });

    let outcome = tokio::select! {
        result = client_to_upstream(
            state,
            &mut client_read,
            &mut upstream_write,
            &client_write,
            &facts,
        ) => result,
        // Upstream closed (or the client's socket died under the copy): the
        // session is over in both directions.
        _ = &mut downstream => Ok(()),
    };
    downstream.abort();
    outcome
}

/// Drive the inspected direction: startup negotiation, then the message loop.
async fn client_to_upstream<R, W>(
    state: &GatewayState,
    client: &mut R,
    upstream: &mut W,
    client_write: &ClientWriter,
    facts: &Facts,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if !startup(client, upstream, client_write).await? {
        return Ok(());
    }
    message_loop(state, client, upstream, client_write, facts).await
}

/// Negotiate the startup phase.
///
/// Returns `true` once a 3.0 `StartupMessage` has been forwarded and the session
/// enters the message phase, `false` when the connection is finished (a
/// `CancelRequest` was relayed, or the client sent something unrecognized).
async fn startup<R, W>(
    client: &mut R,
    upstream: &mut W,
    client_write: &ClientWriter,
) -> std::io::Result<bool>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        // A startup packet is untagged: Int32 length (including itself) then an
        // Int32 code standing in for the protocol version.
        let mut head = [0u8; 8];
        if client.read_exact(&mut head).await.is_err() {
            return Ok(false);
        }
        let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
        let code = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
        if !(8..=MAX_PG_FRAME).contains(&len) {
            return Ok(false);
        }
        let remaining = len - 8;

        match code {
            // Inline inspection needs plaintext between the client and honmoon,
            // so encryption is refused with the single-byte `N` the protocol
            // defines. `sslmode=prefer` clients then send a StartupMessage.
            SSL_REQUEST | GSSENC_REQUEST => {
                if remaining != 0 {
                    return Ok(false);
                }
                let mut writer = client_write.lock().await;
                writer.write_all(b"N").await?;
            }
            PROTOCOL_V3 => {
                upstream.write_all(&head).await?;
                copy_exact(client, upstream, remaining).await?;
                return Ok(true);
            }
            // A cancel connection carries no queries — relay it verbatim.
            CANCEL_REQUEST => {
                upstream.write_all(&head).await?;
                copy_exact(client, upstream, remaining).await?;
                tokio::io::copy(client, upstream).await?;
                return Ok(false);
            }
            _ => {
                tracing::debug!(code, "unsupported PostgreSQL startup packet; closing");
                return Ok(false);
            }
        }
    }
}

/// Frame the client's messages and decide the ones that carry SQL.
async fn message_loop<R, W>(
    state: &GatewayState,
    client: &mut R,
    upstream: &mut W,
    client_write: &ClientWriter,
    facts: &Facts,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        // Every frontend message after startup is `tag(1) | len(4, self-inclusive)`.
        let mut tag = [0u8; 1];
        if client.read_exact(&mut tag).await.is_err() {
            return Ok(()); // client closed
        }
        let mut len_bytes = [0u8; 4];
        client.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len < 4 {
            return Ok(()); // malformed framing; the stream is no longer trustworthy
        }
        let payload_len = len - 4;

        if !matches!(tag[0], b'Q' | b'P') {
            // Not a statement-bearing message (`Bind`, `Execute`, `CopyData`, …).
            // Streamed without buffering — `CopyData` can be arbitrarily large.
            upstream.write_all(&tag).await?;
            upstream.write_all(&len_bytes).await?;
            copy_exact(client, upstream, payload_len).await?;
            continue;
        }

        if len > MAX_PG_FRAME {
            // Fail closed: discard exactly the declared bytes so the stream
            // stays framed, then refuse.
            discard_exact(client, payload_len).await?;
            record(state, facts, None, Decision::Denied, Verdict::Deny);
            refuse(client_write, "honmoon: query frame exceeds inspection cap").await?;
            continue;
        }

        let mut payload = vec![0u8; payload_len];
        client.read_exact(&mut payload).await?;

        let Some(sql) = statement_facts(tag[0], &len_bytes, &payload) else {
            // A `Q`/`P` frame we cannot parse is refused rather than forwarded
            // blind — the same fail-closed posture as the frame cap, and it is
            // audited the same way, so every refusal leaves a trail.
            record(state, facts, None, Decision::Denied, Verdict::Deny);
            refuse(client_write, "honmoon: unparseable query frame").await?;
            continue;
        };

        if decide(state, facts, sql, client_write).await? {
            upstream.write_all(&tag).await?;
            upstream.write_all(&len_bytes).await?;
            upstream.write_all(&payload).await?;
        }
    }
}

/// Extract [`SqlFacts`] from a statement-bearing frame's payload.
fn statement_facts(tag: u8, len_bytes: &[u8; 4], payload: &[u8]) -> Option<SqlFacts> {
    match tag {
        b'Q' => {
            // `parse_postgres_query` validates the whole frame, tag included.
            let mut frame = Vec::with_capacity(5 + payload.len());
            frame.push(b'Q');
            frame.extend_from_slice(len_bytes);
            frame.extend_from_slice(payload);
            parse_postgres_query(&frame)
        }
        b'P' => parse_message_query(payload).map(parse_sql),
        _ => None,
    }
}

/// Extract the query text from a `Parse` (`P`) payload:
/// `statement_name\0 query\0 Int16 nparams …`.
pub(crate) fn parse_message_query(payload: &[u8]) -> Option<&str> {
    let mut parts = payload.splitn(3, |b| *b == 0);
    let _statement_name = parts.next()?;
    let query = parts.next()?;
    // The third piece proves the query string was NUL-terminated rather than
    // truncated at the end of the payload.
    parts.next()?;
    std::str::from_utf8(query).ok()
}

/// Apply the policy to one statement. Returns whether the frame may be forwarded.
async fn decide(
    state: &GatewayState,
    base: &Facts,
    sql: SqlFacts,
    client_write: &ClientWriter,
) -> std::io::Result<bool> {
    let facts = Facts {
        sql: Some(sql),
        ..base.clone()
    };
    let outcome = decide_explained(&state.policy, &facts);

    let allowed = match outcome.verdict {
        Verdict::Allow => {
            // Only a named rule earns an audit entry; auditing every statement
            // would flood the bounded ring.
            if outcome.rule.is_some() {
                record(
                    state,
                    &facts,
                    outcome.rule.clone(),
                    Decision::Allowed,
                    Verdict::Allow,
                );
            }
            true
        }
        Verdict::Deny => {
            record(
                state,
                &facts,
                outcome.rule.clone(),
                Decision::Denied,
                Verdict::Deny,
            );
            false
        }
        Verdict::Pause => {
            let host = facts.domain.clone().unwrap_or_default();
            let summary = FactsSummary::from(&facts);
            let approval = approval_summary(&facts, outcome.rule.as_deref());
            matches!(
                hold(state, &host, summary, outcome.rule.clone(), approval).await,
                HoldOutcome::Approved
            )
        }
    };

    if !allowed {
        refuse(client_write, &denial_message(outcome.rule.as_deref())).await?;
    }
    Ok(allowed)
}

/// Record one decision against the statement's facts.
fn record(
    state: &GatewayState,
    facts: &Facts,
    rule: Option<String>,
    decision: Decision,
    verdict: Verdict,
) {
    state.audit.record(AuditDraft {
        decision,
        verdict,
        rule,
        facts: FactsSummary::from(facts),
        approval_id: None,
    });
}

/// Answer a refused statement with `ErrorResponse` + `ReadyForQuery`, leaving
/// the session open.
async fn refuse(client_write: &ClientWriter, message: &str) -> std::io::Result<()> {
    let mut writer = client_write.lock().await;
    writer.write_all(&error_response(message)).await?;
    writer.write_all(&READY_FOR_QUERY).await
}

/// The message text a refused statement carries back to the client.
fn denial_message(rule: Option<&str>) -> String {
    match rule {
        Some(rule) => format!("honmoon: denied by policy rule {rule}"),
        None => "honmoon: denied by policy".to_owned(),
    }
}

/// A short human description of a held statement, for the approval queue.
fn approval_summary(facts: &Facts, rule: Option<&str>) -> String {
    let target = facts.endpoint.as_deref().unwrap_or("postgres");
    let sql = facts.sql.clone().unwrap_or_default();
    let table = if sql.table.is_empty() {
        String::new()
    } else {
        format!(" {}", sql.table)
    };
    match rule {
        Some(rule) => format!("{} {}{table} (rule: {rule})", target, sql.verb),
        None => format!("{} {}{table}", target, sql.verb),
    }
}

/// Encode an `ErrorResponse` (`E`) carrying SQLSTATE 42501.
pub(crate) fn error_response(message: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for (field, value) in [
        (b'S', "ERROR"),
        (b'V', "ERROR"),
        (b'C', SQLSTATE_INSUFFICIENT_PRIVILEGE),
        (b'M', message),
    ] {
        body.push(field);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0); // end of the field list

    let mut frame = vec![b'E'];
    frame.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    frame
}

/// Copy exactly `len` bytes from `src` to `dst` without buffering them all.
async fn copy_exact<R, W>(src: &mut R, dst: &mut W, mut len: usize) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; COPY_CHUNK.min(len.max(1))];
    while len > 0 {
        let want = len.min(buf.len());
        src.read_exact(&mut buf[..want]).await?;
        dst.write_all(&buf[..want]).await?;
        len -= want;
    }
    Ok(())
}

/// Read and drop exactly `len` bytes, keeping the stream framed.
async fn discard_exact<R>(src: &mut R, mut len: usize) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; COPY_CHUNK.min(len.max(1))];
    while len > 0 {
        let want = len.min(buf.len());
        src.read_exact(&mut buf[..want]).await?;
        len -= want;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_payload(name: &str, query: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(name.as_bytes());
        payload.push(0);
        payload.extend_from_slice(query.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&0i16.to_be_bytes()); // no parameter types
        payload
    }

    #[test]
    fn extracts_the_query_from_a_parse_payload() {
        assert_eq!(
            parse_message_query(&parse_payload("", "TRUNCATE accounts")),
            Some("TRUNCATE accounts")
        );
        assert_eq!(
            parse_message_query(&parse_payload("stmt1", "SELECT 1")),
            Some("SELECT 1")
        );
    }

    #[test]
    fn rejects_a_parse_payload_whose_query_is_unterminated() {
        let mut truncated = Vec::from(b"stmt\0".as_slice());
        truncated.extend_from_slice(b"SELECT 1");
        assert_eq!(parse_message_query(&truncated), None);
        assert_eq!(parse_message_query(b""), None);
    }

    #[test]
    fn error_response_frames_sqlstate_and_message() {
        let frame = error_response("honmoon: denied by policy rule no-drop");
        assert_eq!(frame[0], b'E');
        let len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
        assert_eq!(len + 1, frame.len(), "length covers itself and the body");
        assert_eq!(frame.last(), Some(&0), "field list is NUL-terminated");

        let body = String::from_utf8_lossy(&frame[5..]);
        assert!(body.starts_with("SERROR\0"), "severity first: {body:?}");
        assert!(body.contains("C42501\0"), "SQLSTATE 42501: {body:?}");
        assert!(body.contains("Mhonmoon: denied by policy rule no-drop\0"));
    }
}
