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
//! That answer is injected into a stream the relay is writing at the same time,
//! so it is *ordered* as well as framed: honmoon counts the sync points it
//! forwards and holds the refusal until the relay has delivered the database's
//! `ReadyForQuery` for each of them. Without that barrier a refusal for a
//! pipelined statement would land in front of the response to the statement
//! before it, and the client would attribute the error to the wrong query. What
//! the barrier cannot order is a batch the client drove with `Flush` instead of
//! `Sync`: those responses are answered by no `ReadyForQuery`, so there is
//! nothing to count and nothing to wait for (see [ADR-0007]).
//!
//! A statement held for approval is held *mid-stream*, so the hold also watches
//! the client socket for the disconnect that would otherwise let a human approve
//! a statement for a client that had already left. See [`HeldReader`].
//!
//! [ADR-0007]: ../../../../.please/docs/decisions/0007-inline-postgresql-runtime-semantics.md

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use honmoon_core::{
    AuditDraft, Decision, Facts, FactsSummary, SqlFacts, Verdict, decide_explained,
    protocols::{
        carries_multiple_statements, is_uninspectable_statement, parse_postgres_query, parse_sql,
    },
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, watch};

use crate::approval::{HoldOutcome, hold_until};
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

/// How much traffic a client may pipeline behind a held statement while
/// [`HeldReader::watch_disconnect`] watches for its disconnect. A client
/// waiting for the answer to a paused statement sends at most the rest of its
/// extended-protocol batch (`B`/`D`/`E`/`S`), orders of magnitude below this.
/// Sized to match [`MAX_BUFFERED_BACKEND_MESSAGE`] rather than the 1 MiB frame
/// cap: every held connection can pin this much at once, so the bound that
/// matters is the aggregate across the connection cap, not what one generous
/// client might send.
///
/// Passing it **ends the hold and refuses the statement** rather than parking
/// the watch. Parking would let the client pick the threshold: flooding past
/// the cap and then leaving would restore exactly the behaviour #102 is about,
/// with the hold running to `pause_timeout` and a human approving a statement
/// for a client already gone. Refusing keeps the session alive, which is what
/// ADR-0007 asks of every refusal.
const MAX_HELD_PIPELINE: usize = MAX_BUFFERED_BACKEND_MESSAGE;

/// How long the courtesy answer to an abandoned hold is given to reach the
/// client. The client is gone or has half-closed, so it may not be reading at
/// all: an unbounded write would block on a full send buffer — or on the lock
/// the upstream relay is holding while blocked on the same socket — and pin the
/// session and its upstream connection open for good.
const ABANDONED_NOTICE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The slice of [`ABANDONED_NOTICE_TIMEOUT`] that courtesy answer may spend
/// being *ordered* rather than written.
///
/// [`refuse`] waits for the database's earlier answers before it injects, and
/// on this path the conditions that produced the abandoned hold are the same
/// ones that stall that wait — the client half-closed, so the relay may be
/// blocked writing to a socket nobody is draining. Spending the whole budget
/// there would lose the notice altogether, which is the truncated connection
/// this answer exists to prevent. So ordering gets a slice and the write keeps
/// the rest: a stalled pipeline costs the notice its ordering, never the notice.
const ABANDONED_NOTICE_ORDER_BUDGET: std::time::Duration = std::time::Duration::from_secs(1);

/// How long the upstream→client relay is given to deliver the database's last
/// response after the client stopped sending. Bounded so a server that never
/// closes its half cannot pin the connection open.
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Largest backend message the upstream→client task buffers before switching to
/// a streaming copy. A `DataRow` or `CopyData` can be far larger than this, so an
/// oversized message is copied through in chunks under one held lock rather than
/// held in memory whole.
const MAX_BUFFERED_BACKEND_MESSAGE: usize = 64 * 1024;

/// How long the pipeline may go **without delivering anything** before a
/// waiting refusal gives up on being ordered and injects its answer anyway.
///
/// This bounds the stall, not the whole wait: every response that reaches the
/// client buys another full window, so a database working steadily through a
/// slow statement is never cut off no matter how long the statement runs. Only
/// a pipeline that stops moving altogether expires — which is what the two ways
/// the count can be wrong look like from here: a database that stopped
/// answering, and a sync point the backend swallowed (see
/// [`ClientLink::forwarded_sync_point`]). An unbounded wait would cost the
/// client its answer entirely; injecting late and saying so degrades to exactly
/// the ordering honmoon had before this barrier existed.
const REFUSAL_ORDER_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// A client writer shared between the refusal path and the upstream→client copy
/// task. That task writes one **complete** backend message per lock acquisition,
/// so an injected `ErrorResponse` can only ever land on a message boundary,
/// never inside a server frame. Ordering the refusal *behind* the responses the
/// client has not received yet is a separate guarantee, made by
/// [`ClientLink::await_forwarded_responses`] before this lock is taken.
type ClientWriter = Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>;

/// The client-facing side of a session: the shared writer, the transaction
/// status byte (`I`/`T`/`E`) carried by the last `ReadyForQuery` the upstream
/// sent, and the sync-point counters an injected refusal waits behind.
///
/// A refusal echoes the transaction status instead of always claiming idle —
/// after an allowed `BEGIN` the upstream really is in a transaction, and a
/// driver told otherwise makes transaction-bound decisions on a wrong state.
#[derive(Clone)]
struct ClientLink {
    writer: ClientWriter,
    tx_status: Arc<AtomicU8>,
    /// Sync points forwarded to the database, each of which it answers with
    /// exactly one `ReadyForQuery`: the `StartupMessage`, then every `Q`,
    /// `Sync` and `FunctionCall`. Written only by the message loop.
    ///
    /// Only ever raised. A stalled wait closes its gap by crediting
    /// [`Delivered::sync_points`] instead of lowering this, so that
    /// `sync_points <= forwarded` holds by construction: the two are mutated
    /// from different tasks, and lowering this one leaves a window in which an
    /// answer delivered concurrently is credited against the old, higher value
    /// and survives the subtraction — inverting the pair and releasing the next
    /// refusal before its own answer.
    forwarded: Arc<AtomicU64>,
    /// What the relay has written to the client so far. A watch rather than
    /// plain counters so a refusal can wait on it without polling.
    delivered: Arc<watch::Sender<Delivered>>,
    /// Whether the client's byte stream is still framed. Cleared when the relay
    /// dies partway through writing a backend message, which is the one state in
    /// which injecting a refusal would corrupt rather than explain.
    stream_intact: Arc<std::sync::atomic::AtomicBool>,
}

/// What the relay has delivered to the client.
///
/// # Invariant
///
/// `sync_points <= ClientLink::forwarded`, and it holds by construction rather
/// than by timing. Three things keep it, and an edit that gives up any one of
/// them breaks the ordering guarantee silently:
///
/// 1. `forwarded` only ever rises. Nothing lowers it — a stalled wait closes
///    its gap by crediting `sync_points` here, never by subtracting there.
/// 2. `sync_points` rises only under [`ClientLink::delivered_message`]'s clamp
///    (`< forwarded`) or a write-off's `max(count, expected)`, and `expected`
///    was itself read from `forwarded`, so neither can exceed it.
/// 3. Every mutation of this value goes through the one `send_modify`, so the
///    relay's task and the message loop's cannot interleave inside it.
///
/// Invert the pair and a refusal is released before the answer it was waiting
/// for: the next forwarded statement lifts `forwarded` back to meet an inflated
/// `sync_points`, the barrier reads itself as already drained, and the local
/// answer overtakes a response the client has not been sent — which is the
/// whole of #101.
#[derive(Clone, Copy)]
struct Delivered {
    /// `ReadyForQuery` messages written, or `None` once the relay has stopped
    /// and no further one can arrive. This is what a refusal waits on.
    sync_points: Option<u64>,
    /// Complete backend messages written, of any kind. Never compared against
    /// anything — only watched for change, so that the rows of a slow query
    /// count as progress and hold the stall window open. Without it a query
    /// streaming `DataRow`s for longer than the window would look identical to
    /// a database that had stopped answering, and the refusal queued behind it
    /// would be injected into the middle of its result set.
    messages: u64,
    /// Answers a stalled wait gave up on, and which must therefore be thrown
    /// away rather than counted if the database sends them after all.
    ///
    /// A write-off credits [`Delivered::sync_points`] for answers the client
    /// never received, so that later refusals are not made to pay the stall
    /// bound again. That credit is a fiction, and the database can still
    /// puncture it: PostgreSQL answers in order, so the next `ReadyForQuery`
    /// after a write-off belongs to the oldest unanswered statement — one that
    /// was written off. Counting it would advance `sync_points` into the slot of
    /// a *later* statement whose answer has not arrived, releasing a refusal
    /// queued behind that one ahead of its response, which is #101 again.
    /// Carrying the count here lets each such answer be matched to the write-off
    /// it belongs to and discarded.
    debt: u64,
}

impl ClientLink {
    fn new(writer: tokio::net::tcp::OwnedWriteHalf) -> Self {
        Self {
            writer: Arc::new(Mutex::new(writer)),
            tx_status: Arc::new(AtomicU8::new(STATUS_IDLE)),
            forwarded: Arc::new(AtomicU64::new(0)),
            delivered: Arc::new(watch::Sender::new(Delivered {
                sync_points: Some(0),
                messages: 0,
                debt: 0,
            })),
            stream_intact: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }

    /// Record a frame forwarded to the database that it will answer with a
    /// `ReadyForQuery`.
    ///
    /// Overcounting only stalls a refusal until
    /// [`REFUSAL_ORDER_STALL_TIMEOUT`], which then writes the difference off;
    /// undercounting lets a refusal overtake a response, which is the defect
    /// this exists to prevent. So a message whose sync point is uncertain is
    /// counted — `Sync` among them, which PostgreSQL ignores (and therefore
    /// never answers) while a `COPY` is in progress.
    ///
    /// Called *before* the bytes are written upstream, never after. A fast
    /// database on a multi-threaded runtime can have its `ReadyForQuery` relayed
    /// to the client before the forwarding task runs its next line, and the
    /// clamp in [`ClientLink::delivered_message`] would then discard that answer
    /// as an over-count — leaving the counters skewed by one and making the next
    /// refusal wait out the whole stall window for a response the client already
    /// has. Counting first cannot be too early: a sync point recorded for a
    /// write that then fails costs nothing, because the session ends with it.
    fn forwarded_sync_point(&self) {
        self.forwarded.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one complete backend message written to the client, saying whether
    /// it was the `ReadyForQuery` that ends a request cycle.
    ///
    /// Every message counts as progress and restarts the stall window; only a
    /// sync point advances what a refusal is waiting for. Both are published in
    /// one update so a waiter is woken once — and every read of the counters
    /// happens inside that update, so nothing here can interleave with the
    /// write-off in [`ClientLink::await_forwarded_responses`].
    fn delivered_message(&self, sync_point: bool) {
        let forwarded = &self.forwarded;
        self.delivered.send_modify(|delivered| {
            delivered.messages += 1;
            if !sync_point {
                return;
            }
            let Some(count) = delivered.sync_points.as_mut() else {
                return;
            };
            if delivered.debt > 0 {
                // PostgreSQL answers in order, so this is the oldest statement
                // still unanswered — and a debt means the oldest ones were
                // written off. Their credit was already taken; taking it twice
                // would advance the count into a later statement's slot and
                // release the refusal queued behind *that* one early.
                delivered.debt -= 1;
                return;
            }
            // Never count past what was forwarded. In ordinary operation this
            // cannot bind — every `ReadyForQuery` answers a sync point counted
            // before the frame that earns it goes out — so it stands as a guard
            // against a backend that sends more of them than it was asked for,
            // not as part of the arithmetic. Read inside the update rather than
            // before it, so there is no staleness left for a reader to reason
            // about.
            if *count < forwarded.load(Ordering::Relaxed) {
                *count += 1;
            }
        });
    }

    /// Record that the relay has stopped, releasing every refusal waiting for a
    /// `ReadyForQuery` that can no longer arrive.
    ///
    /// Without this a refusal parked on the barrier would simply be **cancelled**
    /// when the relay's exit completes [`run_postgres`]'s `select!`, and a client
    /// whose own socket is still perfectly healthy would read an unexplained
    /// close instead of its `42501` — the outcome ADR-0007 wrote this answer to
    /// prevent. Ordering is meaningless once nothing is left to be ordered
    /// against, so the wait ends and the answer goes out.
    fn relay_finished(&self) {
        self.delivered
            .send_modify(|delivered| delivered.sync_points = None);
    }

    /// Record that the relay stopped **partway through a backend message**.
    ///
    /// The client already holds a frame header whose payload never arrived, so
    /// its stream is desynchronised and nothing honmoon writes can be read as a
    /// message any more: an injected `ErrorResponse` would be consumed as the
    /// rest of that frame. So the barrier is released — the session is ending
    /// and there is no reason to hold it — but the answer itself is suppressed.
    /// The client gets a truncated connection, which the corruption already
    /// guaranteed; adding bytes to it only makes the truncation harder to read.
    fn relay_desynchronised(&self) {
        self.desynchronise();
        self.relay_finished();
    }

    /// Mark the client's byte stream unframed, without touching the barrier.
    ///
    /// Called by the relay while it still holds the writer lock, so that a
    /// refusal already queued *at* that lock sees the cleared flag when it gets
    /// in rather than the value it read on the way past.
    ///
    /// Both halves of that matter, and neither is sufficient alone. Checking
    /// [`ClientLink::can_inject`] only on the way in lets a refusal that passed
    /// it a moment before the relay's write failed acquire the lock afterwards
    /// and append itself to the partial frame. But *also* checking after the
    /// lock is not enough while the flag is cleared after the guard is dropped:
    /// a refusal arriving in that gap acquires the lock cleanly and still reads
    /// `stream_intact` as true. Only making the state change atomic with the
    /// lock that guards the stream closes it — which is why there is one check,
    /// under the lock, and no cheap early bail-out to reinstate.
    fn desynchronise(&self) {
        self.stream_intact
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether a refusal can still be written as a message the client will
    /// parse as one.
    fn can_inject(&self) -> bool {
        self.stream_intact
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Wait until the client has received the database's answer to every
    /// statement already forwarded on its behalf.
    ///
    /// This is the ordering barrier a locally injected answer sits behind. It
    /// deliberately runs *before* the writer lock is taken: the relay needs that
    /// lock to deliver the very responses being waited for, so holding it here
    /// would deadlock the session instead of ordering it.
    ///
    /// Returns immediately when the pipeline is already drained — the common
    /// case, a client that waits for each answer — and when the relay has
    /// stopped, since nothing is then left to be ordered against.
    async fn await_forwarded_responses(&self) {
        let expected = self.forwarded.load(Ordering::Relaxed);
        let mut delivered = self.delivered.subscribe();
        loop {
            let seen = match delivered.borrow_and_update().sync_points {
                None => return,
                Some(seen) if seen >= expected => return,
                Some(seen) => seen,
            };
            match tokio::time::timeout(REFUSAL_ORDER_STALL_TIMEOUT, delivered.changed()).await {
                // Something arrived — a row, a `CommandComplete`, the sync point
                // itself. It may not be enough yet, but the pipeline is moving,
                // so the stall budget starts over.
                Ok(Ok(())) => {}
                // Every sender is gone. Unreachable while this `ClientLink` is
                // alive, since it owns one — but proceeding in silence would
                // turn a later ownership change into a lost ordering guarantee
                // with nothing in the log to find it by.
                Ok(Err(_)) => {
                    tracing::warn!(
                        expected,
                        delivered = seen,
                        "the delivered-response watch closed while a refusal waited on it"
                    );
                    return;
                }
                Err(_) => {
                    // Not one byte of any backend message for a whole window:
                    // the missing answers are not late, they are not coming.
                    // Write the gap off so the rest of the session is ordered
                    // against what actually arrives — the counters only rise, so
                    // leaving the skew in place would make every later refusal
                    // on this connection pay this bound again.
                    //
                    // The gap is closed by crediting what was delivered, never
                    // by lowering what was forwarded: `forwarded` is written by
                    // this task and read by the relay's, so lowering it leaves a
                    // window in which an answer delivered concurrently is
                    // credited against the old, higher value and survives the
                    // subtraction. Crediting here instead puts both counters
                    // under the one `send_modify` the relay also writes through,
                    // which leaves no interleaving to reason about — and the
                    // count is read from inside that update rather than from the
                    // `seen` sampled before the wait, so an answer that landed
                    // while the timeout was resolving is accounted for rather
                    // than double-counted.
                    //
                    // What is credited is owed back: each written-off answer is
                    // remembered as debt so that, if it turns up after all, it
                    // is discarded rather than advancing the count into a later
                    // statement's slot.
                    self.delivered.send_modify(|delivered| {
                        if let Some(count) = delivered.sync_points.as_mut() {
                            delivered.debt += expected.saturating_sub(*count);
                            *count = (*count).max(expected);
                        }
                    });
                    tracing::warn!(
                        expected,
                        delivered = seen,
                        "no database response for the whole stall window; the refusal may \
                         reach the client out of statement order"
                    );
                    return;
                }
            }
        }
    }
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
    let link = ClientLink::new(client_write);

    let mut downstream = tokio::spawn(upstream_to_client(upstream_read, link.clone()));

    let mut client_sent_everything = false;
    let outcome = tokio::select! {
        // Poll the message loop first. When the relay's exit releases a refusal
        // that was waiting to be ordered behind it, both arms become ready in
        // the same wake-up — and an unbiased `select!` would pick between them
        // at random, dropping the loop half the time before it writes the `42501`
        // it had just been cleared to send. Biased, the loop takes the lock and
        // writes (neither yields once the relay is gone: it released the lock on
        // its way out) and the session ends on the very next poll. Nothing is
        // starved: the arm below is still reached the moment the loop is pending.
        biased;
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
async fn upstream_to_client(upstream: tokio::net::tcp::OwnedReadHalf, link: ClientLink) {
    // Whatever ended the relay — the upstream's EOF, a frame it could no longer
    // trust, a client socket that stopped accepting writes — no further
    // `ReadyForQuery` can reach the client now. Say so, so a refusal waiting to
    // be ordered behind one writes its answer instead of being cancelled
    // unwritten when this task's exit tears the session down.
    match relay_backend_messages(upstream, &link).await {
        RelayEnd::BetweenMessages => link.relay_finished(),
        RelayEnd::MidMessage => link.relay_desynchronised(),
    }
}

/// Where the relay stopped, which decides whether a refusal released by its
/// exit can still be written as a message the client will parse as one.
enum RelayEnd {
    /// On a message boundary. Everything the client received it received whole.
    BetweenMessages,
    /// Partway through writing a backend message, so the client holds a frame
    /// header whose payload never arrived.
    MidMessage,
}

/// The relay's message loop, split out so every way it can end reports where it
/// stopped to [`upstream_to_client`] above exactly once.
async fn relay_backend_messages(
    mut upstream: tokio::net::tcp::OwnedReadHalf,
    link: &ClientLink,
) -> RelayEnd {
    loop {
        // Every backend message is `tag(1) | len(4, self-inclusive) | payload`.
        let mut head = [0u8; 5];
        if upstream.read_exact(&mut head).await.is_err() {
            return RelayEnd::BetweenMessages;
        }
        let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
        if len < 4 {
            // Malformed framing; the stream is no longer trustworthy. Nothing of
            // this message reached the client, so what it already has is whole.
            return RelayEnd::BetweenMessages;
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
                // The header may already be on the client's socket with only
                // part of its payload behind it — `write_all` can fail after a
                // partial write, and the copy fails mid-payload by definition.
                // Marked while the lock is still held, so a refusal waiting for
                // it cannot get in before the flag it checks is cleared.
                link.desynchronise();
                return RelayEnd::MidMessage;
            }
            drop(writer);
            // Oversized by construction, so never a `ReadyForQuery` (six bytes):
            // progress for the stall window, never a sync point.
            link.delivered_message(false);
            continue;
        }

        let mut payload = vec![0u8; payload_len];
        if upstream.read_exact(&mut payload).await.is_err() {
            return RelayEnd::BetweenMessages;
        }
        // `ReadyForQuery` is the only message that states the transaction status.
        if head[0] == b'Z' && !payload.is_empty() {
            link.tx_status.store(payload[0], Ordering::Relaxed);
        }
        {
            let mut writer = link.writer.lock().await;
            if writer.write_all(&head).await.is_err() || writer.write_all(&payload).await.is_err() {
                // Still under the lock: see the oversized branch above.
                link.desynchronise();
                return RelayEnd::MidMessage;
            }
        }
        // Counted only once the client really has the message: a refusal
        // released mid-write would overtake the very response it waited for.
        link.delivered_message(head[0] == b'Z');
    }
}

/// Drive the inspected direction: startup negotiation, then the message loop.
///
/// Returns `true` only when the client's stream ended *cleanly* after its
/// traffic reached the upstream, so the database may still owe a response and
/// the caller should drain. Returns `false` when nothing is owed: the session
/// ended during startup (a relayed `CancelRequest`, an unrecognized packet, or
/// a client that left before negotiating), the connection was reset mid-
/// session, or the client left while a statement of its was held for approval —
/// in none of which is anyone left to read the last response.
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
                // However many authentication round trips follow, the database
                // ends the handshake with exactly one `ReadyForQuery`. Counting
                // it keeps a refusal for a statement the client pipelined behind
                // its startup packet from overtaking the handshake itself —
                // counted before the packet goes out, since the answer can beat
                // this task back.
                link.forwarded_sync_point();
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

/// The client's read half plus a pushback buffer.
///
/// While a statement is held for approval nothing else reads the client socket,
/// and the hold sits inside the `select!` arm [`run_postgres`] races against a
/// still-healthy upstream relay — so neither arm completes and a disconnect goes
/// unnoticed. [`watch_disconnect`](Self::watch_disconnect) closes that window by
/// reading the socket *during* the hold. Anything the client pipelined behind
/// its held statement lands in `pending` and is handed back by the next read, so
/// watching for the disconnect cannot swallow traffic the message loop still
/// owes the upstream.
struct HeldReader<R> {
    inner: R,
    /// Bytes read while watching, not yet handed back.
    pending: Vec<u8>,
    /// How much of `pending` the message loop has already taken.
    taken: usize,
}

impl<R: AsyncRead + Unpin> HeldReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            taken: 0,
        }
    }

    /// Bytes buffered but not yet handed back.
    fn buffered(&self) -> usize {
        debug_assert!(self.taken <= self.pending.len(), "pushback cursor overran");
        self.pending.len() - self.taken
    }

    /// Whether the watch ended because the client filled the pipeline budget
    /// rather than because it left.
    ///
    /// [`watch_disconnect`](Self::watch_disconnect) never reads past the budget,
    /// so it can only leave the buffer exactly full by having stopped on the
    /// cap — which makes this an unambiguous reading of why it returned.
    fn pipeline_full(&self) -> bool {
        self.buffered() >= MAX_HELD_PIPELINE
    }

    /// Resolve once the client is gone, buffering whatever it pipelines first.
    ///
    /// Stays pending while the client is merely quiet — a hold that no client
    /// abandoned must still run to its own timeout. Resolves early once the
    /// client has pipelined [`MAX_HELD_PIPELINE`] bytes, so a flood ends the
    /// hold (fail-closed) instead of growing the buffer without bound or
    /// switching the watch off; [`pipeline_full`](Self::pipeline_full) tells the
    /// two endings apart.
    ///
    /// Cancel-safe: a read that is dropped before it completes has taken
    /// nothing off the socket, so the message loop reads the same bytes later.
    ///
    /// Holds `pending.len() == buffered()` for as long as it runs, so the budget
    /// bounds the whole allocation rather than only its unread tail.
    async fn watch_disconnect(&mut self) {
        // Drop what the message loop already took. Without this the budget below
        // would bound only the unread tail, so a client alternating pauses with
        // partial reads could add a whole budget's worth per hold on top of a
        // consumed prefix that is never reclaimed, and `pending` would grow
        // without bound across a session.
        self.pending.drain(..self.taken);
        self.taken = 0;

        let mut chunk = vec![0u8; COPY_CHUNK];
        loop {
            // Read no further than the budget, so the buffer lands exactly on
            // the cap rather than one chunk past it.
            let budget = MAX_HELD_PIPELINE - self.buffered();
            if budget == 0 {
                tracing::warn!(
                    cap = MAX_HELD_PIPELINE,
                    "client pipelined past the hold watch cap; ending the hold"
                );
                return;
            }
            let want = budget.min(chunk.len());
            match self.inner.read(&mut chunk[..want]).await {
                // A clean end of input: nobody is left to receive the answer to
                // the held statement.
                Ok(0) => return,
                // A reset or an aborted connection. Same conclusion, but say
                // which error reached us — an operator reconstructing a batch of
                // abandoned holds has nothing else to go on.
                Err(e) => {
                    tracing::debug!(error = %e, "client read failed while held");
                    return;
                }
                Ok(n) => self.pending.extend_from_slice(&chunk[..n]),
            }
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for HeldReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.buffered() > 0 {
            let me = &mut *self;
            let n = me.buffered().min(buf.remaining());
            buf.put_slice(&me.pending[me.taken..me.taken + n]);
            me.taken += n;
            if me.taken == me.pending.len() {
                // Release the capacity, not just the length: this reader lives
                // for the whole session, so a `clear()` would pin a held
                // statement's pipeline buffer until the connection closed.
                me.pending = Vec::new();
                me.taken = 0;
            }
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// What the message loop does with a frame the policy has decided.
enum Disposition {
    /// Forward it to the database.
    Forward,
    /// Refuse it; the client has been answered and the session goes on.
    Refused,
    /// The client left while its statement was held for approval. Nothing may
    /// be forwarded on its behalf and there is nobody to answer, so the session
    /// ends here.
    ClientGone,
}

/// Frame the client's messages and decide the ones that carry SQL.
///
/// Returns `true` only for a *clean* end of input between messages: the client
/// finished and may still be waiting for the response to its last query. A
/// reset or aborted connection returns `false`, as does a client that left
/// while one of its statements was held for approval — nothing is waiting for
/// that response, and draining would pin an upstream connection and a task for
/// the whole `DRAIN_TIMEOUT`.
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
    // From here on the client is read through the pushback buffer an approval
    // hold fills while it watches for a disconnect.
    let mut client_reader = HeldReader::new(client);
    loop {
        // Every frontend message after startup is `tag(1) | len(4, self-inclusive)`.
        let mut tag = [0u8; 1];
        match client_reader.read_exact(&mut tag).await {
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
        client_reader.read_exact(&mut len_bytes).await?;
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
            // `Sync` ends an extended-protocol batch and `FunctionCall` is a
            // request cycle of its own; each earns one `ReadyForQuery`. Nothing
            // else does. `Bind` and `Execute` are acknowledged immediately
            // (`BindComplete`, then the rows and `CommandComplete`) but end no
            // cycle, `Terminate` is answered with nothing at all, and what only
            // this counter tracks is the cycle-ending `ReadyForQuery`. Counted
            // before the bytes leave, so the answer cannot beat the count.
            if matches!(tag[0], b'S' | b'F') {
                link.forwarded_sync_point();
            }
            upstream.write_all(&tag).await?;
            upstream.write_all(&len_bytes).await?;
            copy_exact(&mut client_reader, upstream, payload_len).await?;
            continue;
        }

        if len > MAX_PG_FRAME {
            // Fail closed: discard exactly the declared bytes so the stream
            // stays framed, then refuse.
            discard_exact(&mut client_reader, payload_len).await?;
            record(state, facts, None, Decision::Denied, Verdict::Deny);
            refuse(link, "honmoon: query frame exceeds inspection cap").await?;
            continue;
        }

        let mut payload = vec![0u8; payload_len];
        client_reader.read_exact(&mut payload).await?;

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

        match decide(state, facts, sql, link, &mut client_reader).await? {
            Disposition::Forward => {
                // A simple query is its own request cycle. A `Parse` is
                // acknowledged at once with `ParseComplete`, but its batch does
                // not end until the client's `Sync` — which is counted where
                // that `Sync` is forwarded, not here. Counted before the write,
                // so a database that answers immediately cannot have its
                // `ReadyForQuery` discarded as an over-count.
                if tag[0] == b'Q' {
                    link.forwarded_sync_point();
                }
                upstream.write_all(&tag).await?;
                upstream.write_all(&len_bytes).await?;
                upstream.write_all(&payload).await?;
            }
            Disposition::Refused => {}
            // No drain: the client that would have read the answer is gone.
            Disposition::ClientGone => return Ok(false),
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

/// Apply the policy to one statement, telling the caller what to do with its
/// frame.
///
/// `client` is only touched on the `pause` path, where the hold watches it for
/// the disconnect that would otherwise let an approved statement run for a
/// client that is already gone.
async fn decide<R>(
    state: &GatewayState,
    base: &Facts,
    sql: SqlFacts,
    link: &ClientLink,
    client: &mut HeldReader<R>,
) -> std::io::Result<Disposition>
where
    R: AsyncRead + Unpin,
{
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
            let held = hold_until(
                state,
                &host,
                summary,
                outcome.rule.clone(),
                approval,
                client.watch_disconnect(),
            )
            .await;
            match held {
                HoldOutcome::Approved => true,
                // The client flooded the watch budget instead of leaving, so it
                // may well still be there. Fail closed on the statement, but
                // keep the session: ADR-0007 asks that a refusal never be
                // collateral damage for the connection.
                HoldOutcome::Abandoned if client.pipeline_full() => false,
                HoldOutcome::Abandoned => {
                    // The client is gone — or it half-closed and is still
                    // reading, which arrives as the same EOF and cannot be told
                    // apart on this socket. Answer before ending the session, so
                    // a client that is still there learns why its statement
                    // never ran instead of seeing the connection truncated. One
                    // that really left just makes this write fail, harmlessly.
                    // Bounded: a client that half-closed and then stopped
                    // reading would otherwise block this write — directly, or on
                    // the writer lock the relay holds while blocked on the same
                    // socket — and the session would never end at all. Ordering
                    // takes only a slice of that budget rather than going
                    // through `refuse`: the same half-close that ended the hold
                    // is what stalls the pipeline, so spending the whole budget
                    // on the wait would leave nothing for the answer itself.
                    let _ = tokio::time::timeout(ABANDONED_NOTICE_TIMEOUT, async {
                        let _ = tokio::time::timeout(
                            ABANDONED_NOTICE_ORDER_BUDGET,
                            link.await_forwarded_responses(),
                        )
                        .await;
                        write_refusal(
                            link,
                            "honmoon: connection ended while the statement was held for approval",
                        )
                        .await
                    })
                    .await;
                    return Ok(Disposition::ClientGone);
                }
                HoldOutcome::Rejected | HoldOutcome::QueueFull => false,
            }
        }
    };

    if !allowed {
        refuse(link, &denial_message(outcome.rule.as_deref())).await?;
        return Ok(Disposition::Refused);
    }
    Ok(Disposition::Forward)
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
///
/// The answer is injected in PostgreSQL request order: it waits for the database
/// to finish answering the statements the client sent before this one, so a
/// client that pipelined `SELECT pg_sleep(1); DROP TABLE users;` reads the
/// `SELECT`'s response first and attributes the `42501` to the statement it
/// belongs to.
async fn refuse(link: &ClientLink, message: &str) -> std::io::Result<()> {
    link.await_forwarded_responses().await;
    write_refusal(link, message).await
}

/// Write the `ErrorResponse`/`ReadyForQuery` pair, without ordering it.
///
/// Split from [`refuse`] for the one caller that has to budget the two phases
/// separately — see [`ABANDONED_NOTICE_ORDER_BUDGET`]. Every other refusal goes
/// through [`refuse`] and is ordered.
async fn write_refusal(link: &ClientLink, message: &str) -> std::io::Result<()> {
    let mut writer = link.writer.lock().await;
    if !link.can_inject() {
        // The relay died partway through a backend message, so the client is
        // holding a frame header whose payload never came. It would read these
        // bytes as that payload's remainder, turning a truncated connection into
        // a corrupted one. Say nothing; the session is ending either way.
        //
        // Checked here rather than on the way in: the relay clears the flag
        // while it still holds this lock, so a refusal that queued behind its
        // failing write has to see the cleared value, not the one that was true
        // when it started waiting.
        return Ok(());
    }
    // Read after any wait and under the lock, so the status echoed back is the
    // one from the last `ReadyForQuery` the client actually received.
    let status = link.tx_status.load(Ordering::Relaxed);
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
    use crate::approval::ApprovalDecision;

    /// A `ClientLink` backed by a real loopback connection: the writer is a
    /// concrete `OwnedWriteHalf`, so it cannot be faked with an in-memory buffer.
    /// The peer socket comes back with it and must be kept alive by the caller.
    async fn loopback_link() -> (ClientLink, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let (_read, write) = client.unwrap().into_split();
        (ClientLink::new(write), accepted.unwrap().0)
    }

    /// Spawn the upstream→client relay over a loopback pair, returning the
    /// socket that stands in for the database. Writing a backend message to it
    /// is how a test decides *when* the client is answered.
    async fn loopback_relay(link: ClientLink) -> (TcpStream, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (database, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        // The relay only ever reads; dropping the write half just half-closes a
        // direction nothing in these tests uses.
        let (read, _write) = accepted.unwrap().0.into_split();
        (
            database.unwrap(),
            tokio::spawn(upstream_to_client(read, link)),
        )
    }

    /// Read one whole backend message off the client socket, returning its tag.
    /// Deliberately unbounded: every caller states its own deadline, and an
    /// inner timer of its own would be the first to fire under a paused clock.
    async fn read_message_tag(peer: &mut TcpStream) -> u8 {
        let mut head = [0u8; 5];
        peer.read_exact(&mut head)
            .await
            .expect("the client is answered");
        let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
        let mut payload = vec![0u8; len - 4];
        peer.read_exact(&mut payload).await.unwrap();
        head[0]
    }

    /// A policy that denies every `DROP`.
    fn deny_drop_policy() -> honmoon_core::Policy {
        honmoon_core::Policy::from_yaml(
            "egress:\n  default: allow\nrules:\n  - name: no-drop\n    endpoint: '*'\n    condition: \"sql.verb == 'DROP'\"\n    verdict: deny\n",
        )
        .expect("valid policy")
    }

    /// What a database answers a `Q` with: `CommandComplete` + `ReadyForQuery`.
    fn query_response() -> Vec<u8> {
        let tag = b"SELECT 1\0";
        let mut frames = vec![b'C'];
        frames.extend_from_slice(&((4 + tag.len()) as u32).to_be_bytes());
        frames.extend_from_slice(tag);
        frames.extend_from_slice(&[b'Z', 0, 0, 0, 5, b'I']);
        frames
    }

    /// The pipelined pair the client sends in the ordering tests: an allowed
    /// statement the database is still working on, then a denied one.
    fn pipelined_select_then_drop() -> Vec<u8> {
        let mut frames = simple_query("SELECT pg_sleep(1)");
        frames.extend_from_slice(&simple_query("DROP TABLE users"));
        frames
    }

    /// A `P` (Parse) frame carrying `query`, as the client puts it on the wire.
    fn parse_frame(name: &str, query: &str) -> Vec<u8> {
        let payload = parse_payload(name, query);
        let mut frame = vec![b'P'];
        frame.extend_from_slice(&((4 + payload.len()) as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        frame
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

    /// A `Q` frame carrying `sql`, as the client puts it on the wire.
    fn simple_query(sql: &str) -> Vec<u8> {
        let mut frame = vec![b'Q'];
        frame.extend_from_slice(&((5 + sql.len()) as u32).to_be_bytes());
        frame.extend_from_slice(sql.as_bytes());
        frame.push(0);
        frame
    }

    /// A policy that holds every `DELETE` for a human.
    fn pause_delete_policy() -> honmoon_core::Policy {
        honmoon_core::Policy::from_yaml(
            "egress:\n  default: allow\nrules:\n  - name: review-delete\n    endpoint: '*'\n    condition: \"sql.verb == 'DELETE'\"\n    verdict: pause\n",
        )
        .expect("valid policy")
    }

    #[tokio::test]
    async fn a_client_that_leaves_mid_hold_cancels_its_approval_and_forwards_nothing() {
        let state = GatewayState::new(pause_delete_policy());
        // The client sends a statement the policy pauses, then goes away. The
        // hold used to sit there until `pause_timeout` regardless — long enough
        // for a human to approve a statement for a client that no longer
        // existed (#102). The tie between a decision and a simultaneous
        // disconnect is a separate question, settled by
        // `a_decision_already_in_hand_beats_a_simultaneous_abandonment`.
        let mut client = std::io::Cursor::new(simple_query("DELETE FROM sessions"));
        let mut upstream: Vec<u8> = Vec::new();
        let (link, mut peer) = loopback_link().await;

        let drain = message_loop(&state, &mut client, &mut upstream, &link, &Facts::default())
            .await
            .unwrap();

        assert!(
            upstream.is_empty(),
            "a statement whose client is gone must never reach the database"
        );
        assert!(
            !drain,
            "nobody is left to read the answer, so nothing is owed"
        );
        assert!(
            state.approvals.is_empty(),
            "the abandoned hold released its approval slot"
        );
        assert!(
            state
                .approvals
                .resolve(1, ApprovalDecision::Approve)
                .is_none(),
            "a human can no longer approve the statement after its client left"
        );

        // A client that half-closed and is still reading writes the same EOF, so
        // the session is not truncated in silence: whoever is still there is
        // told why the statement never ran.
        let mut answer = [0u8; 1];
        peer.read_exact(&mut answer)
            .await
            .expect("an abandoned client is still answered");
        assert_eq!(answer[0], b'E');
    }

    #[tokio::test]
    async fn a_second_watch_does_not_stack_its_budget_on_consumed_bytes() {
        // A client that alternates paused statements with partial reads keeps a
        // consumed prefix in the buffer. If the budget were measured against the
        // unread tail alone, every hold would add another budget's worth on top
        // of that prefix and the buffer would grow without bound over a session.
        let mut reader = HeldReader::new(std::io::Cursor::new(vec![b'x'; MAX_HELD_PIPELINE * 3]));
        reader.watch_disconnect().await;
        assert!(reader.pipeline_full(), "the first watch fills its budget");

        let mut half = vec![0u8; MAX_HELD_PIPELINE / 2];
        reader.read_exact(&mut half).await.unwrap();
        reader.watch_disconnect().await;

        assert_eq!(
            reader.buffered(),
            MAX_HELD_PIPELINE,
            "the second watch refills to the same budget"
        );
        assert_eq!(
            reader.pending.len(),
            MAX_HELD_PIPELINE,
            "and holds nothing beyond it — the consumed prefix was reclaimed"
        );
    }

    /// Yields `head`, then never resolves again — a client that has sent
    /// something and is still connected, so the watch must not read it as gone.
    struct StallAfter {
        head: std::io::Cursor<Vec<u8>>,
    }

    impl AsyncRead for StallAfter {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if (self.head.position() as usize) < self.head.get_ref().len() {
                return std::pin::Pin::new(&mut self.head).poll_read(cx, buf);
            }
            std::task::Poll::Pending
        }
    }

    #[tokio::test]
    async fn a_client_that_floods_the_watch_budget_is_refused_and_keeps_its_session() {
        let state = GatewayState::new(pause_delete_policy());
        // A paused statement followed by more than the watch will buffer. Parking
        // the watch here instead would hand the client the threshold: it could
        // flood past the cap, leave, and still have its statement approved and
        // executed — the very defect #102 is about. So the hold ends and the
        // statement is refused, and the session survives it (ADR-0007).
        let mut frames = simple_query("DELETE FROM sessions");
        // `Sync` frames: well-formed, carry no statement, and are streamed
        // through untouched — so the only thing the flood can prove is what the
        // held `DELETE` did.
        while frames.len() < simple_query("DELETE FROM sessions").len() + MAX_HELD_PIPELINE + 1 {
            frames.extend_from_slice(&[b'S', 0, 0, 0, 4]);
        }
        let mut client = StallAfter {
            head: std::io::Cursor::new(frames),
        };
        let mut upstream: Vec<u8> = Vec::new();
        let (link, mut peer) = loopback_link().await;

        let facts = Facts::default();
        let loop_run = message_loop(&state, &mut client, &mut upstream, &link, &facts);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), loop_run).await;

        assert!(
            outcome.is_err(),
            "the session survives the refusal rather than ending with it"
        );
        assert!(
            !upstream
                .windows(b"DELETE FROM sessions".len())
                .any(|w| w == b"DELETE FROM sessions"),
            "a statement whose hold ended without approval must not reach the database"
        );
        assert!(
            state.approvals.is_empty(),
            "the hold released its approval slot"
        );
        assert!(
            state
                .approvals
                .resolve(1, ApprovalDecision::Approve)
                .is_none(),
            "flooding cannot leave a statement approvable after the fact"
        );

        let mut answer = [0u8; 1];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            peer.read_exact(&mut answer),
        )
        .await
        .expect("the client is answered")
        .expect("the client is answered");
        assert_eq!(answer[0], b'E', "the client is told the statement failed");
    }

    #[tokio::test]
    async fn bytes_pipelined_behind_a_held_statement_survive_the_disconnect_watch() {
        // Watching for the disconnect reads the client socket, so whatever the
        // client pipelined behind its held statement has to come back out of the
        // pushback buffer rather than being swallowed.
        let mut reader = HeldReader::new(std::io::Cursor::new(b"SYNC".to_vec()));
        reader.watch_disconnect().await;

        let mut first = [0u8; 2];
        reader.read_exact(&mut first).await.unwrap();
        let mut rest = [0u8; 2];
        reader.read_exact(&mut rest).await.unwrap();
        assert_eq!(&first, b"SY");
        assert_eq!(&rest, b"NC", "a partial take leaves the remainder buffered");
        assert_eq!(reader.buffered(), 0);
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

    #[tokio::test]
    async fn a_refusal_waits_for_the_response_to_a_statement_already_forwarded() {
        let state = GatewayState::new(deny_drop_policy());
        // The `SELECT` is forwarded and the database is still working on it when
        // the `DROP` is refused. Injecting straight away would put honmoon's
        // 42501 in front of the `SELECT`'s response, and the client would
        // attribute the error to the statement it already had answered (#101).
        let mut client = std::io::Cursor::new(pipelined_select_then_drop());
        let mut upstream: Vec<u8> = Vec::new();
        let (link, mut peer) = loopback_link().await;
        let (mut database, _relay) = loopback_relay(link.clone()).await;

        let facts = Facts::default();
        let session = message_loop(&state, &mut client, &mut upstream, &link, &facts);
        let client_view = async {
            let mut early = [0u8; 1];
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    peer.read_exact(&mut early),
                )
                .await
                .is_err(),
                "the refusal overtook the response to the statement before it"
            );

            // Only now does the database answer the `SELECT`.
            database.write_all(&query_response()).await.unwrap();

            let seen = [
                read_message_tag(&mut peer).await,
                read_message_tag(&mut peer).await,
                read_message_tag(&mut peer).await,
                read_message_tag(&mut peer).await,
            ];
            assert_eq!(
                seen,
                [b'C', b'Z', b'E', b'Z'],
                "the client reads the two answers in the order it asked the questions"
            );
        };

        let (drain, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(session, client_view)
        })
        .await
        .expect("the session finished");
        assert!(
            drain.unwrap(),
            "the client sent everything it had and the session ended cleanly"
        );
        assert!(
            !upstream
                .windows(b"DROP TABLE users".len())
                .any(|w| w == b"DROP TABLE users"),
            "waiting for the earlier response must not forward the denied statement"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_database_costs_one_stall_window_and_is_then_written_off() {
        let state = GatewayState::new(deny_drop_policy());
        // Sitting behind an earlier response must not become a way to lose the
        // refusal altogether: the relay is alive but the database says nothing,
        // so the `SELECT`'s `ReadyForQuery` never arrives and the wait expires.
        // The answer that never came is then written off — the counters are
        // monotonic, so leaving the skew would make the *second* `DROP` pay the
        // same window again, and every refusal after it for the whole session.
        let mut frames = pipelined_select_then_drop();
        frames.extend_from_slice(&simple_query("DROP TABLE accounts"));
        let mut client = std::io::Cursor::new(frames);
        let mut upstream: Vec<u8> = Vec::new();
        let (link, mut peer) = loopback_link().await;
        let (_database, _relay) = loopback_relay(link.clone()).await;

        let started = tokio::time::Instant::now();
        let facts = Facts::default();
        let session = message_loop(&state, &mut client, &mut upstream, &link, &facts);
        let client_view = async {
            for _ in 0..2 {
                assert_eq!(
                    read_message_tag(&mut peer).await,
                    b'E',
                    "a silent database costs the refusal its ordering, never the client its answer"
                );
                assert_eq!(read_message_tag(&mut peer).await, b'Z');
            }
        };

        let (drain, ()) = tokio::join!(session, client_view);
        assert!(drain.unwrap(), "the session survives the late refusals");
        assert_eq!(
            started.elapsed(),
            REFUSAL_ORDER_STALL_TIMEOUT,
            "one stall window for the whole session, not one per refusal"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_pipeline_that_keeps_moving_never_hits_the_stall_bound() {
        // The bound is on the stall, not on the wait. Two answers are owed and
        // each arrives just inside a window, so every delivery buys another one
        // and the barrier releases on the second answer instead of expiring —
        // a database working steadily through a statement that outlives one
        // window is ordered properly rather than cut off.
        //
        // Driven straight against the link: a real socket in the wait path
        // would let the paused clock jump to the stall deadline before the
        // relay's read completes, and the test would measure the bound it is
        // meant to prove is not reached.
        let (link, _peer) = loopback_link().await;
        link.forwarded_sync_point();
        link.forwarded_sync_point();
        let step = REFUSAL_ORDER_STALL_TIMEOUT - std::time::Duration::from_secs(5);

        let started = tokio::time::Instant::now();
        let answers = async {
            for _ in 0..2 {
                tokio::time::sleep(step).await;
                link.delivered_message(true);
            }
        };
        tokio::join!(link.await_forwarded_responses(), answers);

        assert_eq!(
            started.elapsed(),
            2 * step,
            "the wait ended on the last answer, not on the stall bound"
        );
        assert_eq!(
            link.forwarded.load(Ordering::Relaxed),
            2,
            "nothing was written off — every answer arrived"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn rows_streaming_out_of_a_slow_query_hold_the_stall_window_open() {
        // Only `ReadyForQuery` advances what a refusal waits *for*, but every
        // backend message is progress. A query streaming `DataRow`s for longer
        // than the window is a database working, not one that stopped — and
        // treating it as stopped would inject the refusal into the middle of
        // that result set, which is worse than the misattribution #101 removed.
        let (link, _peer) = loopback_link().await;
        link.forwarded_sync_point();
        let step = REFUSAL_ORDER_STALL_TIMEOUT - std::time::Duration::from_secs(5);

        let started = tokio::time::Instant::now();
        let answers = async {
            // Two windows' worth of rows, and only then the sync point.
            for _ in 0..2 {
                tokio::time::sleep(step).await;
                link.delivered_message(false);
            }
            tokio::time::sleep(step).await;
            link.delivered_message(true);
        };
        tokio::join!(link.await_forwarded_responses(), answers);

        assert_eq!(started.elapsed(), 3 * step, "rows counted as progress");
        assert_eq!(
            link.forwarded.load(Ordering::Relaxed),
            1,
            "a working database is never written off"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_written_off_and_then_delivered_late_is_not_counted_twice() {
        // A write-off credits the delivered count for an answer the client
        // never got. If the answer then turns up, counting it as well would
        // take that credit twice and release the *next* refusal before its own
        // answer — losing the ordering the write-off was only meant to make
        // affordable.
        let (link, _peer) = loopback_link().await;
        link.forwarded_sync_point();
        link.await_forwarded_responses().await;
        assert_eq!(
            link.forwarded.load(Ordering::Relaxed),
            1,
            "a write-off never lowers what was forwarded"
        );
        assert_eq!(
            (
                link.delivered.borrow().sync_points,
                link.delivered.borrow().debt
            ),
            (Some(1), 1),
            "the answer that never came was credited, and remembered as owed"
        );

        // The database was slow, not silent: the answer arrives after all.
        link.delivered_message(true);
        assert_eq!(
            (
                link.delivered.borrow().sync_points,
                link.delivered.borrow().debt
            ),
            (Some(1), 0),
            "a late answer to a written-off statement is discarded, not credited"
        );

        // So the next statement's refusal still waits for its own answer.
        link.forwarded_sync_point();
        assert!(
            tokio::time::timeout(
                REFUSAL_ORDER_STALL_TIMEOUT / 2,
                link.await_forwarded_responses(),
            )
            .await
            .is_err(),
            "the refusal after a write-off is still ordered behind its own answer"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_late_written_off_answer_does_not_release_a_refusal_behind_a_later_query() {
        // The dangerous shape is a write-off, *then* another query, *then* the
        // written-off answer. Matching that answer against what was forwarded
        // is not enough — the later query raised that ceiling, so the stale
        // answer fits under it and is credited to a slot it does not own,
        // releasing the refusal queued behind the later query before the
        // database has answered it. That is #101, reached the long way round.
        let (link, _peer) = loopback_link().await;

        // Query A goes out and is never answered.
        link.forwarded_sync_point();
        link.await_forwarded_responses().await;

        // Query B goes out while A is still owed.
        link.forwarded_sync_point();
        // A's answer finally arrives — B's has not.
        link.delivered_message(true);

        assert!(
            tokio::time::timeout(
                REFUSAL_ORDER_STALL_TIMEOUT / 2,
                link.await_forwarded_responses(),
            )
            .await
            .is_err(),
            "a written-off statement's late answer does not answer for the statement after it"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_query_forwarded_after_a_write_off_is_still_released_by_its_own_answer() {
        // The other half of the same rule, and the easy thing to break while
        // fixing the first: discarding late answers must not leave the barrier
        // permanently one short, or every refusal for the rest of the session
        // pays the stall bound again — which is what the write-off exists to
        // prevent.
        let (link, _peer) = loopback_link().await;

        link.forwarded_sync_point();
        link.await_forwarded_responses().await;
        link.forwarded_sync_point();
        // A's late answer is discarded against the debt, then B's own answers B.
        link.delivered_message(true);
        link.delivered_message(true);

        let started = tokio::time::Instant::now();
        link.await_forwarded_responses().await;
        assert_eq!(
            started.elapsed(),
            std::time::Duration::ZERO,
            "the statement after a write-off is released by its own answer, at once"
        );
    }

    #[tokio::test]
    async fn a_relay_that_dies_mid_message_suppresses_the_refusal_rather_than_corrupting_it() {
        // The client holds a frame header whose payload never arrived, so its
        // stream is already desynchronised: it would read an injected
        // `ErrorResponse` as that payload's remainder. A truncated connection is
        // the honest outcome; adding bytes to it makes the truncation unreadable.
        let (link, mut peer) = loopback_link().await;
        link.relay_desynchronised();

        write_refusal(&link, "honmoon: denied by policy")
            .await
            .unwrap();

        drop(link);
        let mut trailing = Vec::new();
        peer.read_to_end(&mut trailing).await.unwrap();
        assert!(
            trailing.is_empty(),
            "nothing may follow a partial frame, got {trailing:?}"
        );
    }

    #[tokio::test]
    async fn a_refusal_queued_at_the_writer_lock_sees_the_stream_break_under_it() {
        // The mid-frame check has to happen *inside* the writer lock. A refusal
        // that passes it on the way in, then waits for the lock the relay is
        // holding while its own write fails, would otherwise append itself to
        // the partial frame the relay just left behind.
        let (link, mut peer) = loopback_link().await;
        let held = Arc::clone(&link.writer).lock_owned().await;

        let refusing = tokio::spawn({
            let link = link.clone();
            async move { write_refusal(&link, "honmoon: denied by policy").await }
        });
        // Current-thread runtime: one yield is enough to run the task up to the
        // point where it blocks on the lock, which is its first await.
        tokio::task::yield_now().await;

        // The relay's write fails partway through a frame and it marks the
        // stream unframed before letting go of the lock.
        link.desynchronise();
        drop(held);
        refusing.await.unwrap().unwrap();

        drop(link);
        let mut trailing = Vec::new();
        peer.read_to_end(&mut trailing).await.unwrap();
        assert!(
            trailing.is_empty(),
            "a refusal that was already waiting for the lock must still be suppressed, \
             got {trailing:?}"
        );
    }

    /// An upstream that answers the instant a byte reaches it, by recording the
    /// `ReadyForQuery` the relay would have delivered. This is the interleaving
    /// a fast database on a multi-threaded runtime produces: the answer can be
    /// on the client's socket before the forwarding task runs its next line.
    struct AnswersBeforeTheWriteReturns {
        link: ClientLink,
        answered: bool,
    }

    impl AsyncWrite for AnswersBeforeTheWriteReturns {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if !self.answered {
                self.answered = true;
                self.link.delivered_message(true);
            }
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_that_beats_the_forward_being_recorded_is_not_discarded() {
        // Sync points are counted before the bytes go out precisely so this
        // ordering is impossible. Counting afterwards lets the clamp in
        // `delivered_message` read a stale `forwarded` and throw the answer
        // away, and the counters stay one apart for the rest of the session —
        // every later refusal then waits out the whole stall window for a
        // response the client is already holding.
        let (link, _peer) = loopback_link().await;
        let mut client = std::io::Cursor::new(startup_packet(PROTOCOL_V3, b"user\0pg\0\0"));
        let mut upstream = AnswersBeforeTheWriteReturns {
            link: link.clone(),
            answered: false,
        };

        assert!(startup(&mut client, &mut upstream, &link).await.unwrap());

        let started = tokio::time::Instant::now();
        link.await_forwarded_responses().await;
        assert_eq!(
            started.elapsed(),
            std::time::Duration::ZERO,
            "the handshake was answered, so nothing is owed and the refusal waits for nothing"
        );
    }

    #[tokio::test]
    async fn a_relay_that_stops_releases_the_refusal_waiting_behind_it() {
        let state = GatewayState::new(deny_drop_policy());
        // The database goes away while the refusal is queued behind its answer.
        // Nothing is left to order against, so the wait must end at once: a
        // refusal still parked here is cancelled unwritten when the relay's exit
        // ends the session, and a client whose own socket is fine reads an
        // unexplained close instead of its 42501 (ADR-0007).
        let mut client = std::io::Cursor::new(pipelined_select_then_drop());
        let mut upstream: Vec<u8> = Vec::new();
        let (link, mut peer) = loopback_link().await;
        let (database, _relay) = loopback_relay(link.clone()).await;

        let facts = Facts::default();
        let session = message_loop(&state, &mut client, &mut upstream, &link, &facts);
        let client_view = async {
            // Nothing may arrive while the database is merely quiet...
            let mut early = [0u8; 1];
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    peer.read_exact(&mut early),
                )
                .await
                .is_err(),
                "the refusal overtook the response to the statement before it"
            );
            // ...but the moment the database is gone, the answer goes out.
            drop(database);
            assert_eq!(read_message_tag(&mut peer).await, b'E');
            assert_eq!(read_message_tag(&mut peer).await, b'Z');
        };

        let (drain, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(session, client_view)
        })
        .await
        .expect("the refusal is written as soon as the relay ends, not after the stall bound");
        assert!(drain.unwrap());
    }

    #[tokio::test]
    async fn a_refusal_waits_for_an_extended_protocol_batch_ended_by_sync() {
        let state = GatewayState::new(deny_drop_policy());
        // The path every driver using prepared statements takes. `Parse` earns
        // no `ReadyForQuery` of its own — the batch's `Sync` does — so the
        // refusal has to wait behind the `Sync`, not behind the `Parse`.
        let mut frames = parse_frame("stmt", "SELECT 1");
        frames.extend_from_slice(&[b'S', 0, 0, 0, 4]);
        frames.extend_from_slice(&simple_query("DROP TABLE users"));
        let mut client = std::io::Cursor::new(frames);
        let mut upstream: Vec<u8> = Vec::new();
        let (link, mut peer) = loopback_link().await;
        let (mut database, _relay) = loopback_relay(link.clone()).await;

        let facts = Facts::default();
        let session = message_loop(&state, &mut client, &mut upstream, &link, &facts);
        let client_view = async {
            let mut early = [0u8; 1];
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    peer.read_exact(&mut early),
                )
                .await
                .is_err(),
                "the refusal overtook the batch it was pipelined behind"
            );

            // `ParseComplete`, then the `Sync`'s `ReadyForQuery`.
            database.write_all(&[b'1', 0, 0, 0, 4]).await.unwrap();
            database.write_all(&[b'Z', 0, 0, 0, 5, b'I']).await.unwrap();

            let seen = [
                read_message_tag(&mut peer).await,
                read_message_tag(&mut peer).await,
                read_message_tag(&mut peer).await,
                read_message_tag(&mut peer).await,
            ];
            assert_eq!(seen, [b'1', b'Z', b'E', b'Z']);
        };

        let (drain, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(session, client_view)
        })
        .await
        .expect("the session finished");
        assert!(drain.unwrap());
    }

    /// A connected loopback pair: the end a test drives, and the end handed to
    /// the code under test.
    async fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (near, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (near.unwrap(), accepted.unwrap().0)
    }

    #[tokio::test]
    async fn an_upstream_that_closes_mid_refusal_still_lets_the_client_be_told() {
        let state = GatewayState::new(deny_drop_policy());
        // The whole session, not just the message loop: the relay's exit both
        // releases the waiting refusal *and* completes the future `run_postgres`
        // races the loop against, so the two become ready together. An unbiased
        // `select!` drops the loop half the time and the client — whose own
        // socket is fine — reads an unexplained close instead of its 42501,
        // which is the outcome ADR-0007 wrote the injected answer to prevent.
        let (mut client, client_end) = socket_pair().await;
        let (upstream_end, mut database) = socket_pair().await;

        let session = tokio::spawn(async move {
            run_postgres(&state, client_end, upstream_end, Facts::default()).await
        });

        client
            .write_all(&startup_packet(PROTOCOL_V3, b"user\0me\0\0"))
            .await
            .unwrap();
        // Answer the handshake, so the only response still owed is the SELECT's.
        let mut startup_seen = vec![0u8; 13];
        database.read_exact(&mut startup_seen).await.unwrap();
        database.write_all(&[b'Z', 0, 0, 0, 5, b'I']).await.unwrap();
        assert_eq!(read_message_tag(&mut client).await, b'Z');

        // Pipeline an allowed statement the database never answers, then a
        // denied one, and drop the database while the refusal waits behind it.
        client
            .write_all(&pipelined_select_then_drop())
            .await
            .unwrap();
        let mut forwarded = vec![0u8; simple_query("SELECT pg_sleep(1)").len()];
        database.read_exact(&mut forwarded).await.unwrap();
        drop(database);

        let told = async {
            assert_eq!(read_message_tag(&mut client).await, b'E');
            assert_eq!(read_message_tag(&mut client).await, b'Z');
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), told)
            .await
            .expect("the client is told why its statement was refused");

        session.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_refusal_waits_for_the_startup_handshake_it_was_pipelined_behind() {
        let state = GatewayState::new(deny_drop_policy());
        // A client that puts a statement on the wire behind its startup packet
        // without waiting to be authenticated. The handshake ends in exactly one
        // `ReadyForQuery`, so the refusal belongs behind it — injecting first
        // would answer a statement before the session it runs in exists.
        let mut frames = startup_packet(PROTOCOL_V3, b"user\0me\0\0");
        frames.extend_from_slice(&simple_query("DROP TABLE users"));
        let mut client = std::io::Cursor::new(frames);
        let mut upstream: Vec<u8> = Vec::new();
        let (link, mut peer) = loopback_link().await;
        let (mut database, _relay) = loopback_relay(link.clone()).await;

        let facts = Facts::default();
        let session = client_to_upstream(&state, &mut client, &mut upstream, &link, &facts);
        let client_view = async {
            let mut early = [0u8; 1];
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    peer.read_exact(&mut early),
                )
                .await
                .is_err(),
                "the refusal overtook the handshake it was pipelined behind"
            );

            // `AuthenticationOk`, then the handshake's `ReadyForQuery`.
            database
                .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0])
                .await
                .unwrap();
            database.write_all(&[b'Z', 0, 0, 0, 5, b'I']).await.unwrap();

            let seen = [
                read_message_tag(&mut peer).await,
                read_message_tag(&mut peer).await,
                read_message_tag(&mut peer).await,
                read_message_tag(&mut peer).await,
            ];
            assert_eq!(seen, [b'R', b'Z', b'E', b'Z']);
        };

        let (drain, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(session, client_view)
        })
        .await
        .expect("the session finished");
        assert!(drain.unwrap());
        assert!(
            !upstream
                .windows(b"DROP TABLE users".len())
                .any(|w| w == b"DROP TABLE users"),
            "the denied statement never reached the database"
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
