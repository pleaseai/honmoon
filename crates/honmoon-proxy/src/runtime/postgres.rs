//! Inline PostgreSQL protocol runtime (see [ADR-0007]).
//!
//! Sits between a client that dialed a `protocol: postgres` endpoint through
//! the SOCKS5 listener and the real database. Every frame the client sends is
//! framed; `Q` (simple query) and `P` (Parse, extended protocol) carry SQL, so
//! their statement is parsed into [`SqlFacts`](honmoon_core::SqlFacts) and
//! decided by the policy engine before a byte reaches the database. Everything
//! else is streamed through untouched, and the upstream→client direction is
//! relayed uninspected — framed only so a refusal cannot land inside a server
//! message.
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
use std::sync::atomic::{AtomicU8, Ordering};

use honmoon_core::{
    AuditDraft, Decision, Facts, FactsSummary, SqlFacts, Verdict, decide_explained,
    protocols::{
        carries_multiple_statements, is_uninspectable_statement, parse_postgres_query, parse_sql,
    },
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

/// Transaction status a session starts in, before the upstream has sent its
/// first `ReadyForQuery`: idle.
const STATUS_IDLE: u8 = b'I';

/// SQLSTATE 42501 — insufficient privilege. The closest standard code to "a
/// policy refused this", and one every driver already surfaces sensibly.
const SQLSTATE_INSUFFICIENT_PRIVILEGE: &str = "42501";

/// Copy buffer for the pass-through paths.
const COPY_CHUNK: usize = 16 * 1024;

/// How long the upstream→client relay is given to deliver the database's last
/// response after the client stopped sending. Bounded so a server that never
/// closes its half cannot pin the connection open.
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Largest backend message the upstream→client task buffers before switching to
/// a streaming copy. A `DataRow` or `CopyData` can be far larger than this, so an
/// oversized message is copied through in chunks under one held lock rather than
/// held in memory whole.
const MAX_BUFFERED_BACKEND_MESSAGE: usize = 64 * 1024;

/// A client writer shared between the refusal path and the upstream→client copy
/// task. That task writes one **complete** backend message per lock acquisition,
/// so an injected `ErrorResponse` can only ever land on a message boundary,
/// never inside a server frame. It does not order the refusal against responses
/// the client has not read yet — only framing is guarded here.
type ClientWriter = Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>;

/// The client-facing side of a session: the shared writer, plus the transaction
/// status byte (`I`/`T`/`E`) carried by the last `ReadyForQuery` the upstream
/// sent. A refusal echoes that status instead of always claiming idle — after an
/// allowed `BEGIN` the upstream really is in a transaction, and a driver told
/// otherwise makes transaction-bound decisions on a wrong state.
#[derive(Clone)]
struct ClientLink {
    writer: ClientWriter,
    tx_status: Arc<AtomicU8>,
}

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
    let (upstream_read, mut upstream_write) = upstream.into_split();
    let link = ClientLink {
        writer: Arc::new(Mutex::new(client_write)),
        tx_status: Arc::new(AtomicU8::new(STATUS_IDLE)),
    };

    let mut downstream = tokio::spawn(upstream_to_client(upstream_read, link.clone()));

    let mut client_sent_everything = false;
    let outcome = tokio::select! {
        result = client_to_upstream(
            state,
            &mut client_read,
            &mut upstream_write,
            &link,
            &facts,
        ) => {
            // Only a *clean* end of a stream that reached the message phase
            // earns the drain below. An error means the client is gone or its
            // stream desynced, and a session that ended during startup never
            // forwarded a query, so in neither case is a last response still
            // owed — draining anyway would let an abandoned session pin an
            // upstream connection and a task for the whole `DRAIN_TIMEOUT`.
            client_sent_everything = matches!(result, Ok(true));
            result.map(|_| ())
        }
        // Upstream closed (or the client's socket died under the copy): the
        // session is over in both directions.
        _ = &mut downstream => Ok(()),
    };

    // The client sent everything it had. Half-close the upstream write half so
    // the database sees the end of input and flushes whatever it still owes,
    // then let the relay deliver it. Aborting straight away instead would
    // truncate the response to a client that sent its last query and shut down
    // its write half before reading.
    if client_sent_everything {
        let _ = upstream_write.shutdown().await;
        let _ = tokio::time::timeout(DRAIN_TIMEOUT, &mut downstream).await;
    }
    downstream.abort();
    outcome
}

/// Relay upstream→client, one complete backend message at a time.
///
/// Framing matters here even though nothing in this direction is inspected: the
/// writer is shared with the refusal path, so writing a message in several
/// locked chunks would let an `ErrorResponse` land inside a server frame and
/// desynchronise the client. Each message is written under a single lock, and
/// every `ReadyForQuery` publishes its transaction status for [`refuse`].
async fn upstream_to_client(mut upstream: tokio::net::tcp::OwnedReadHalf, link: ClientLink) {
    loop {
        // Every backend message is `tag(1) | len(4, self-inclusive) | payload`.
        let mut head = [0u8; 5];
        if upstream.read_exact(&mut head).await.is_err() {
            return;
        }
        let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
        if len < 4 {
            return; // malformed framing; the stream is no longer trustworthy
        }
        let payload_len = len - 4;

        if payload_len > MAX_BUFFERED_BACKEND_MESSAGE {
            // Too large to hold in memory. Take the lock for the whole copy so a
            // refusal still cannot slip into the middle of it.
            let mut writer = link.writer.lock().await;
            if writer.write_all(&head).await.is_err()
                || copy_exact(&mut upstream, &mut *writer, payload_len)
                    .await
                    .is_err()
            {
                return;
            }
            continue;
        }

        let mut payload = vec![0u8; payload_len];
        if upstream.read_exact(&mut payload).await.is_err() {
            return;
        }
        // `ReadyForQuery` is the only message that states the transaction status.
        if head[0] == b'Z' && !payload.is_empty() {
            link.tx_status.store(payload[0], Ordering::Relaxed);
        }
        let mut writer = link.writer.lock().await;
        if writer.write_all(&head).await.is_err() || writer.write_all(&payload).await.is_err() {
            return;
        }
    }
}

/// Drive the inspected direction: startup negotiation, then the message loop.
///
/// Returns `true` only when the client's stream ended *cleanly* after its
/// traffic reached the upstream, so the database may still owe a response and
/// the caller should drain. Returns `false` when nothing is owed: the session
/// ended during startup (a relayed `CancelRequest`, an unrecognized packet, or
/// a client that left before negotiating), or the connection was reset mid-
/// session, where no one is left to read the last response.
async fn client_to_upstream<R, W>(
    state: &GatewayState,
    client: &mut R,
    upstream: &mut W,
    link: &ClientLink,
    facts: &Facts,
) -> std::io::Result<bool>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if !startup(client, upstream, link).await? {
        return Ok(false);
    }
    message_loop(state, client, upstream, link, facts).await
}

/// Negotiate the startup phase.
///
/// Returns `true` once a 3.0 `StartupMessage` has been forwarded and the session
/// enters the message phase, `false` when the connection is finished (a
/// `CancelRequest` was relayed, or the client sent something unrecognized).
async fn startup<R, W>(client: &mut R, upstream: &mut W, link: &ClientLink) -> std::io::Result<bool>
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
                let mut writer = link.writer.lock().await;
                writer.write_all(b"N").await?;
            }
            PROTOCOL_V3 => {
                upstream.write_all(&head).await?;
                copy_exact(client, upstream, remaining).await?;
                return Ok(true);
            }
            // A cancel connection carries no queries — relay the packet verbatim
            // and stop. `CancelRequest` is self-contained, so waiting for the
            // client's EOF afterwards would only pin the runtime and the upstream
            // connection for as long as the client cares to hold the socket.
            CANCEL_REQUEST => {
                upstream.write_all(&head).await?;
                copy_exact(client, upstream, remaining).await?;
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
///
/// Returns `true` only for a *clean* end of input between messages: the client
/// finished and may still be waiting for the response to its last query. A
/// reset or aborted connection returns `false` — nothing is waiting for that
/// response, and draining would pin an upstream connection and a task for the
/// whole `DRAIN_TIMEOUT`.
async fn message_loop<R, W>(
    state: &GatewayState,
    client: &mut R,
    upstream: &mut W,
    link: &ClientLink,
    facts: &Facts,
) -> std::io::Result<bool>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        // Every frontend message after startup is `tag(1) | len(4, self-inclusive)`.
        let mut tag = [0u8; 1];
        match client.read_exact(&mut tag).await {
            Ok(_) => {}
            // A clean end of input on a message boundary: the client sent
            // everything it had, and the database may still owe a response.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(true),
            // A reset or aborted connection. Nobody is left to read the last
            // response, so draining would just hold an upstream connection and
            // a task open for `DRAIN_TIMEOUT` — which a client can repeat until
            // the connection cap is exhausted.
            Err(_) => return Ok(false),
        }
        let mut len_bytes = [0u8; 4];
        client.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len < 4 {
            // A protocol violation, not a clean shutdown: say so rather than
            // reporting the session as having ended normally.
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed framing: length less than 4",
            ));
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
            refuse(link, "honmoon: query frame exceeds inspection cap").await?;
            continue;
        }

        let mut payload = vec![0u8; payload_len];
        client.read_exact(&mut payload).await?;

        // A simple query may legally carry several statements, but `parse_sql`
        // only ever sees the first verb — `SELECT 1; DROP TABLE users` would be
        // decided as a `SELECT` and forwarded whole. Nothing downstream re-reads
        // the rest, so the frame is refused rather than forwarded uninspected.
        if tag[0] == b'Q' && payload_carries_multiple_statements(&payload) {
            record(state, facts, None, Decision::Denied, Verdict::Deny);
            refuse(
                link,
                "honmoon: multi-statement query frames are not inspectable",
            )
            .await?;
            continue;
        }

        // A `DO` block runs an arbitrary PL/pgSQL body while reporting the
        // harmless verb `DO`, and the body is not SQL, so there is nothing to
        // classify — the statements inside it are simply unreachable. Refuse the
        // frame, the same fail-closed answer a batch gets. Unlike the batch
        // check this applies to `P` as well as `Q`: a `DO` block can be prepared.
        if frame_query(tag[0], &payload).is_some_and(is_uninspectable_statement) {
            record(state, facts, None, Decision::Denied, Verdict::Deny);
            refuse(link, "honmoon: DO blocks are not inspectable").await?;
            continue;
        }

        let Some(sql) = statement_facts(tag[0], &len_bytes, &payload) else {
            // A `Q`/`P` frame we cannot parse is refused rather than forwarded
            // blind — the same fail-closed posture as the frame cap, and it is
            // audited the same way, so every refusal leaves a trail.
            record(state, facts, None, Decision::Denied, Verdict::Deny);
            refuse(link, "honmoon: unparseable query frame").await?;
            continue;
        };

        if decide(state, facts, sql, link).await? {
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

/// The SQL text a statement-bearing frame carries, whichever tag delivered it.
/// `None` when the payload does not decode — the caller's unparseable-frame path
/// refuses those.
fn frame_query(tag: u8, payload: &[u8]) -> Option<&str> {
    match tag {
        // A `Q` payload is the query text plus its NUL terminator.
        b'Q' => payload
            .strip_suffix(&[0])
            .and_then(|query| std::str::from_utf8(query).ok()),
        b'P' => parse_message_query(payload),
        _ => None,
    }
}

/// Whether a simple-query (`Q`) payload carries more than one statement.
///
/// The scanner itself is [`carries_multiple_statements`] in `honmoon-core`,
/// shared with the comment-stripping [`parse_sql`] does. A payload that does not
/// decode is left to the caller's unparseable-frame path.
fn payload_carries_multiple_statements(payload: &[u8]) -> bool {
    frame_query(b'Q', payload).is_some_and(carries_multiple_statements)
}

/// Apply the policy to one statement. Returns whether the frame may be forwarded.
async fn decide(
    state: &GatewayState,
    base: &Facts,
    sql: SqlFacts,
    link: &ClientLink,
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
        refuse(link, &denial_message(outcome.rule.as_deref())).await?;
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
/// the session open. The `ReadyForQuery` reports the transaction status honmoon
/// last saw upstream, so a refusal inside an open transaction does not tell the
/// client it is idle.
async fn refuse(link: &ClientLink, message: &str) -> std::io::Result<()> {
    let status = link.tx_status.load(Ordering::Relaxed);
    let mut writer = link.writer.lock().await;
    writer.write_all(&error_response(message)).await?;
    writer.write_all(&[b'Z', 0, 0, 0, 5, status]).await
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

    /// A `ClientLink` backed by a real loopback connection: the writer is a
    /// concrete `OwnedWriteHalf`, so it cannot be faked with an in-memory buffer.
    /// The peer socket comes back with it and must be kept alive by the caller.
    async fn loopback_link() -> (ClientLink, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let (_read, write) = client.unwrap().into_split();
        let link = ClientLink {
            writer: Arc::new(Mutex::new(write)),
            tx_status: Arc::new(AtomicU8::new(STATUS_IDLE)),
        };
        (link, accepted.unwrap().0)
    }

    fn startup_packet(code: u32, body: &[u8]) -> Vec<u8> {
        let len = 8 + body.len();
        let mut packet = Vec::with_capacity(len);
        packet.extend_from_slice(&(len as u32).to_be_bytes());
        packet.extend_from_slice(&code.to_be_bytes());
        packet.extend_from_slice(body);
        packet
    }

    #[tokio::test]
    async fn a_session_that_never_leaves_startup_does_not_ask_for_a_drain() {
        let state = GatewayState::new(honmoon_core::Policy::default());
        let mut client = std::io::Cursor::new(startup_packet(0xDEAD_BEEF, b""));
        let mut upstream: Vec<u8> = Vec::new();
        let (link, _peer) = loopback_link().await;

        let drain =
            client_to_upstream(&state, &mut client, &mut upstream, &link, &Facts::default())
                .await
                .unwrap();

        assert!(
            !drain,
            "an unrecognized startup packet forwards nothing upstream, so no response is owed"
        );
        assert!(upstream.is_empty(), "nothing reached the upstream");
    }

    /// Yields `head`, then fails with `kind` — a client that resets rather than
    /// closing cleanly.
    struct ResetAfter {
        head: std::io::Cursor<Vec<u8>>,
        kind: std::io::ErrorKind,
    }

    impl AsyncRead for ResetAfter {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if (self.head.position() as usize) < self.head.get_ref().len() {
                return std::pin::Pin::new(&mut self.head).poll_read(cx, buf);
            }
            std::task::Poll::Ready(Err(std::io::Error::new(self.kind, "reset")))
        }
    }

    #[tokio::test]
    async fn a_client_that_resets_mid_session_does_not_ask_for_a_drain() {
        let state = GatewayState::new(honmoon_core::Policy::default());
        // A valid startup packet reaches the upstream, then the client RSTs
        // before sending a single frontend message. Nobody is left to read a
        // response, so holding the upstream for DRAIN_TIMEOUT would let a
        // client repeat this until the connection cap is exhausted.
        let mut client = ResetAfter {
            head: std::io::Cursor::new(startup_packet(PROTOCOL_V3, b"user\0me\0\0")),
            kind: std::io::ErrorKind::ConnectionReset,
        };
        let mut upstream: Vec<u8> = Vec::new();
        let (link, _peer) = loopback_link().await;

        let drain =
            client_to_upstream(&state, &mut client, &mut upstream, &link, &Facts::default())
                .await
                .unwrap();

        assert!(!drain, "a reset connection is not a clean end of input");
        assert!(
            !upstream.is_empty(),
            "the startup packet still reached the upstream"
        );
    }

    #[tokio::test]
    async fn a_session_that_reaches_the_message_phase_asks_for_a_drain() {
        let state = GatewayState::new(honmoon_core::Policy::default());
        // A 3.0 StartupMessage, then EOF: the client sent everything it had.
        let mut client = std::io::Cursor::new(startup_packet(PROTOCOL_V3, b"user\0me\0\0"));
        let mut upstream: Vec<u8> = Vec::new();
        let (link, _peer) = loopback_link().await;

        let drain =
            client_to_upstream(&state, &mut client, &mut upstream, &link, &Facts::default())
                .await
                .unwrap();

        assert!(
            drain,
            "the startup packet reached the upstream, so its response must still be drained"
        );
    }

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

    /// A `Q` payload is the query text plus its NUL terminator.
    fn q_payload(query: &str) -> Vec<u8> {
        let mut payload = Vec::from(query.as_bytes());
        payload.push(0);
        payload
    }

    #[test]
    fn multi_statement_payloads_are_recognized_and_single_ones_are_not() {
        assert!(payload_carries_multiple_statements(&q_payload(
            "SELECT 1; DROP TABLE users"
        )));
        assert!(!payload_carries_multiple_statements(&q_payload(
            "SELECT 1;"
        )));
        assert!(
            !payload_carries_multiple_statements(b"SELECT 1; DROP TABLE users"),
            "a payload with no NUL terminator is the unparseable path's business"
        );
    }

    #[test]
    fn a_do_block_is_recognized_in_both_statement_bearing_tags() {
        // `DO $$ … $$` is one statement, so the batch check waves it through;
        // the frame is refused for being uninspectable instead. It reaches the
        // runtime as either tag, so both extractions have to see it.
        let block = "DO $$ BEGIN DELETE FROM users; END $$";
        assert!(!payload_carries_multiple_statements(&q_payload(block)));
        assert!(frame_query(b'Q', &q_payload(block)).is_some_and(is_uninspectable_statement));
        assert!(
            frame_query(b'P', &parse_payload("stmt", block))
                .is_some_and(is_uninspectable_statement)
        );

        // An ordinary statement is still decided by policy, not refused.
        assert!(!frame_query(b'Q', &q_payload("SELECT 1")).is_some_and(is_uninspectable_statement));
        assert!(
            !frame_query(b'P', &parse_payload("", "DROP TABLE users"))
                .is_some_and(is_uninspectable_statement)
        );
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
