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
//! **The relay owns the client write half.** Honmoon never writes to the client
//! from the task that reads it: the message loop hands what it wants written to
//! the upstream→client relay over a channel ([`Injection`]) and the relay writes
//! it between two complete backend messages. That is what makes the two things
//! such an answer has to get right structural rather than guarded:
//!
//! - **Framing.** The relay is the only writer and writes one whole backend
//!   message at a time, so an injection cannot land inside a server frame. When
//!   a write fails partway through a message the relay drops the writer with
//!   itself, so nothing can be appended to the partial frame the client is left
//!   holding — there is no flag to check, because there is no writer to check it
//!   with.
//! - **Order.** Honmoon counts the sync points it forwards and tags each
//!   injection with the count as it stood when the refusal was decided; the
//!   relay writes it once it has delivered that many `ReadyForQuery` frames.
//!   Without that a refusal for a pipelined statement would land in front of the
//!   response to the statement before it, and the client would attribute the
//!   error to the wrong query. What the sync-point count cannot order is a batch
//!   the client drove with `Flush` instead of `Sync`: those responses are
//!   answered by no `ReadyForQuery`, so `Flush` frames are counted separately
//!   and settled by the relay finding the upstream quiet at a message boundary
//!   (see [ADR-0007]).
//!
//! A statement held for approval is held *mid-stream*, so the hold also watches
//! the client socket for the disconnect that would otherwise let a human approve
//! a statement for a client that had already left. See [`HeldReader`].
//!
//! [ADR-0007]: ../../../../.please/docs/decisions/0007-inline-postgresql-runtime-semantics.md

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use honmoon_core::{
    AuditDraft, Decision, Facts, FactsSummary, SqlFacts, Verdict, decide_explained,
    protocols::{
        carries_multiple_statements, is_uninspectable_statement, parse_postgres_query, parse_sql,
    },
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

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
/// all: an unbounded wait would leave the relay blocked on a full send buffer
/// and pin the session and its upstream connection open for good.
const ABANDONED_NOTICE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The slice of [`ABANDONED_NOTICE_TIMEOUT`] that courtesy answer may spend
/// being *ordered* rather than written.
///
/// Every other refusal waits for the database's earlier answers until the stall
/// bound, and on this path the conditions that produced the abandoned hold are
/// the same ones that stall that wait — the client half-closed, so the relay may
/// be blocked writing to a socket nobody is draining. Spending the whole budget
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
/// oversized message is copied through in chunks rather than held in memory
/// whole.
const MAX_BUFFERED_BACKEND_MESSAGE: usize = 64 * 1024;

/// How long the pipeline may go **without delivering anything** before a queued
/// refusal gives up on being ordered and is written anyway.
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
///
/// The timer lives in the relay, which is the task that knows whether any
/// backend traffic has arrived, so "waiting on sync point N with nothing from
/// the database for T" is one local decision rather than an inference from a
/// counter another task publishes.
const REFUSAL_ORDER_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Frames honmoon has forwarded that the database still owes the client an
/// answer for, as the message loop counts them.
///
/// One-way by construction: every field is written only by the message loop and
/// read only by the relay, and **only ever raised**. Nothing lowers anything
/// here. What the client has actually received is counted by the relay, in
/// [`Relay`], and never published back — so there is no pair of counters two
/// tasks can invert between them, and a wait that gives up records that on its
/// own side rather than rewinding these.
struct Forwarded {
    /// Sync points forwarded to the database, each of which it answers with
    /// exactly one `ReadyForQuery`: the `StartupMessage`, then every `Q`,
    /// `Sync` and `FunctionCall`.
    sync_points: AtomicU64,
    /// `Flush` (`H`) frames forwarded to the database.
    ///
    /// A `Flush` earns no `ReadyForQuery` — PostgreSQL answers it with whatever
    /// is already pending — so a pipelining client that drives its batches with
    /// `Flush` and sends `Sync` only at the end of the pipeline, or never,
    /// registers nothing above and would not be ordered against at all. That was
    /// #113. Counted separately rather than folded into `sync_points` because the
    /// two are settled by different observations: a sync point by the
    /// `ReadyForQuery` that answers it, a flush by the relay running out of
    /// bytes to relay (see [`Relay::flush_drained`]). Sharing one counter would
    /// let a sync point's answer settle a flush, and a quiet upstream settle a
    /// sync point the database is still computing.
    flushes: AtomicU64,
    /// [`Forwarded::flushes`] as it stood when the most recent sync point was
    /// forwarded — the flushes that sync point's `ReadyForQuery` will answer for.
    ///
    /// PostgreSQL answers in order, so a `ReadyForQuery` proves every frame
    /// before its `Sync` has been processed and its output emitted, flushed
    /// output included. A sync point therefore subsumes every `Flush` already
    /// outstanding, and is a far better settlement for them than waiting for the
    /// upstream to fall quiet: a batch ending `Flush`/`Sync` — which is what a
    /// libpq pipeline does at `PQpipelineSync()` — normally arrives as one
    /// burst, so the relay sees no quiet before the `Z` and would otherwise
    /// leave the flush outstanding for the whole stall window.
    ///
    /// Snapshotted at forward time rather than read live, because a `Flush`
    /// *after* a `Sync` is not answered by that `Sync`'s `ReadyForQuery`.
    ///
    /// Still one snapshot rather than one per forwarded sync point, so with two
    /// `Sync` frames in flight the earlier `ReadyForQuery` can read the later
    /// one's value. That is #153, and it is unchanged here: the premature credit
    /// cannot release a refusal while the sync side still holds the barrier, and
    /// making it exact needs per-sync-point state whose size a client controls.
    flushes_covered: AtomicU64,
}

impl Forwarded {
    fn new() -> Self {
        Self {
            sync_points: AtomicU64::new(0),
            flushes: AtomicU64::new(0),
            flushes_covered: AtomicU64::new(0),
        }
    }
}

/// A frame honmoon writes to the client on its own behalf, handed to the relay
/// because the relay owns the client write half for the whole session.
enum Injection {
    /// The single byte `N` that refuses encryption during startup. The session
    /// has not begun and the database has been sent nothing, so there is no
    /// response stream to order it against.
    NoEncryption,
    /// `ErrorResponse` (SQLSTATE 42501) + `ReadyForQuery` for a refused
    /// statement, ordered behind everything the client is still owed.
    Refusal(Refusal),
}

/// A refused statement's answer, and where in the response stream it belongs.
struct Refusal {
    /// The message text the `ErrorResponse` carries.
    message: String,
    /// Sync points forwarded when the refusal was decided. The relay writes the
    /// answer once it has delivered this many `ReadyForQuery` frames.
    sync_points: u64,
    /// `Flush` frames forwarded when the refusal was decided.
    flushes: u64,
    /// The latest instant the relay may hold the answer back for ordering, for
    /// the one caller that has to budget ordering and writing apart (see
    /// [`ABANDONED_NOTICE_ORDER_BUDGET`]). `None` takes the ordinary stall bound.
    order_deadline: Option<tokio::time::Instant>,
}

/// An injection and the acknowledgement the message loop waits for.
struct Injected {
    what: Injection,
    /// Resolves once the relay has written it, and is dropped unsent when the
    /// relay cannot — it has stopped, or its writer is gone because the client's
    /// stream is no longer framed. The caller cannot tell those apart and does
    /// not need to: in both cases nothing honmoon writes will reach the client
    /// through this channel again.
    written: oneshot::Sender<()>,
}

/// The relay could not write what it was handed.
struct Unwritten;

/// The message loop's end of the session: the counters it raises before a frame
/// goes upstream, and the channel it hands the answers honmoon writes itself to.
///
/// It holds no client writer, which is the point. There is no lock to take in
/// the wrong order, no flag saying whether writing is still safe, and no way to
/// write into a backend frame the relay is halfway through — because there is no
/// way to write at all.
#[derive(Clone)]
struct ClientLink {
    forwarded: Arc<Forwarded>,
    /// Capacity one: every injection is awaited to completion before the message
    /// loop reads another client frame, so one slot is all there can ever be in
    /// flight — and a queue that can hold one thing is a queue whose order
    /// cannot be wrong.
    injections: mpsc::Sender<Injected>,
}

impl ClientLink {
    /// Record a frame forwarded to the database that it will answer with a
    /// `ReadyForQuery`.
    ///
    /// Overcounting stalls a refusal; undercounting lets one overtake a
    /// response, which is the defect this exists to prevent. So a message whose
    /// sync point is uncertain is counted — `Sync` among them, which PostgreSQL
    /// ignores (and therefore never answers) while a `COPY` is in progress.
    ///
    /// Be clear about what that costs, because it is more than one stall. A
    /// point that is merely slow costs [`REFUSAL_ORDER_STALL_TIMEOUT`] once and
    /// is then settled, because the relay remembers what it gave up on. A point
    /// that can *never* be answered is given up on the same way, but the next
    /// statement raises the count a later refusal is measured against while the
    /// relay's delivered count stays where it was, so **every** later refusal on
    /// the connection pays a stall window too. The trade is still the right way
    /// round — the failure is latency, never a refusal overtaking a response —
    /// but it is a recurring cost, not a one-time one. That is #128.
    ///
    /// Called *before* the bytes are written upstream, never after. A fast
    /// database on a multi-threaded runtime can have its `ReadyForQuery` relayed
    /// to the client before the forwarding task runs its next line, and the
    /// clamp in [`Relay::delivered`] would then discard that answer as an
    /// over-count — leaving the counts skewed by one and making the next refusal
    /// wait out the whole stall window for a response the client already has.
    /// Counting first cannot be too early: a sync point recorded for a write that
    /// then fails costs nothing, because the session ends with it.
    fn forwarded_sync_point(&self) {
        // Everything already forwarded is answered before this frame's
        // `ReadyForQuery`, flushed output included, so this sync point speaks
        // for every `Flush` outstanding right now. Recorded before the count
        // rises, and read by [`Relay::delivered`] when the answer lands. See
        // [`Forwarded::flushes_covered`].
        self.forwarded.flushes_covered.store(
            self.forwarded.flushes.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.forwarded.sync_points.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a `Flush` forwarded to the database, which it answers with
    /// whatever output it already has pending and no `ReadyForQuery` at all.
    ///
    /// Counted before the bytes go out, for the reason
    /// [`ClientLink::forwarded_sync_point`] gives: the relay settles this from
    /// its own task, and a settlement that beat the count would be read as
    /// belonging to nothing.
    ///
    /// What it costs when it is wrong is the same trade, in the same direction.
    /// A `Flush` that elicits nothing at all — one sent with no pending output,
    /// or one the backend ignores because a `COPY` is in progress — is never
    /// settled, so the next refusal pays one [`REFUSAL_ORDER_STALL_TIMEOUT`] and
    /// is then given up on. Not counting it is the other failure, and it is #113
    /// itself: the refusal overtakes a response the client has not been sent.
    fn forwarded_flush(&self) {
        self.forwarded.flushes.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot what the client is still owed, so the relay can order an answer
    /// behind it.
    ///
    /// Read here rather than in the relay because the message loop is the only
    /// writer of these counts: they cannot move under it, and the flush coverage
    /// it reads is exactly the snapshot the most recent forwarded sync point
    /// left — no later one exists yet.
    fn refusal(&self, message: &str, order_deadline: Option<tokio::time::Instant>) -> Refusal {
        Refusal {
            message: message.to_owned(),
            sync_points: self.forwarded.sync_points.load(Ordering::Relaxed),
            flushes: self.forwarded.flushes.load(Ordering::Relaxed),
            order_deadline,
        }
    }

    /// Hand an injection to the relay and wait for it to be written.
    async fn inject(&self, what: Injection) -> Result<(), Unwritten> {
        let (written, ack) = oneshot::channel();
        if self
            .injections
            .send(Injected { what, written })
            .await
            .is_err()
        {
            return Err(Unwritten);
        }
        ack.await.map_err(|_| Unwritten)
    }
}

/// The upstream read half as the relay uses it: an awaited read (through
/// [`AsyncRead`]) plus one attempt that reports "nothing right now" instead of
/// waiting.
///
/// That second operation is the only signal the wire carries that a `Flush`'s
/// output has been delivered in full, and it is a trait rather than the concrete
/// half so the relay's ordering can be driven with no socket in the wait path: a
/// paused clock jumps to the next timer deadline while a real socket's readiness
/// is still in flight, so a test that asserts the stall bound is *not* reached
/// cannot have one.
trait TryRead {
    /// Read whatever is already buffered, returning
    /// [`std::io::ErrorKind::WouldBlock`] rather than waiting for more.
    fn try_read_now(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
}

impl TryRead for tokio::net::tcp::OwnedReadHalf {
    fn try_read_now(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.try_read(buf)
    }
}

/// Why the relay stopped, which decides whether the client's byte stream is
/// still framed — and therefore whether the writer is handed back at all.
enum Stop {
    /// The upstream direction ended: EOF, a frame the relay could no longer
    /// trust, or a read that failed. Everything the client received it received
    /// whole.
    Upstream,
    /// A write to the client failed. `write_all` can fail after a partial write
    /// and a streaming copy fails mid-payload by definition, so the client may be
    /// holding a frame header whose payload never arrived.
    Client,
}

/// What the relay hands back when it stops with the client's stream still
/// framed: the write half, and the transaction status of the last
/// `ReadyForQuery` it delivered.
///
/// Handing the writer back is how a refusal decided *after* the relay stopped is
/// still answered, and withholding it is how one decided after a partial frame
/// is suppressed. There is no flag either way — a caller that has no writer
/// cannot write, and a caller that has one is writing to a stream that can still
/// read what it says.
struct HandBack {
    client: tokio::net::tcp::OwnedWriteHalf,
    tx_status: u8,
}

/// The relay's own view of the session: the client writer it owns outright, and
/// what the client has actually received.
///
/// Every count here is written and read by this one task, so none of it needs to
/// be atomic and none of it can interleave. In particular there is no *debt*:
/// [`Relay::answered`] and [`Relay::drained`] only ever count what the client
/// really received, and a wait that gives up records that separately in
/// [`Relay::abandoned`] / [`Relay::abandoned_flushes`]. The earlier design
/// credited the delivered counts for answers that never arrived and then had to
/// remember the credit so a late answer was not counted twice; keeping the two
/// apart makes that bookkeeping unnecessary rather than merely easier.
struct Relay {
    /// The client write half. Nothing else in the process holds one.
    client: tokio::net::tcp::OwnedWriteHalf,
    forwarded: Arc<Forwarded>,
    /// The one injection taken off the channel and not yet written.
    queued: Option<Injected>,
    /// Set when a bound expired on the queued answer: it is written on the next
    /// check whether or not the client has received what it was owed.
    forced: bool,
    /// When the queued answer stops waiting to be ordered. Armed when it is
    /// queued and re-armed by every message delivered, so the bound is on the
    /// stall and not on the wait.
    stall_deadline: Option<tokio::time::Instant>,
    /// Whether the message loop's end of the channel is gone. It closes when the
    /// session's inspected direction ends; the relay keeps going, because the
    /// database may still owe the client its last response.
    injections_closed: bool,
    /// `ReadyForQuery` frames written to the client. This is what a refusal
    /// tagged with a sync-point count waits for.
    answered: u64,
    /// Sync points the relay gave up waiting for. A floor beside `answered`
    /// rather than a credit to it: a refusal is released once *either* reaches
    /// its tag, so the rest of the session is ordered against what actually
    /// arrives, while an answer that turns up after all still raises `answered`
    /// truthfully and cannot be counted twice.
    abandoned: u64,
    /// `Flush` frames whose output the relay has seen drained: it delivered at
    /// least one message the flush could have produced, and then found the
    /// upstream socket empty at a message boundary.
    drained: u64,
    /// `Flush` frames the relay gave up waiting for — the flush counterpart to
    /// [`Relay::abandoned`], and a floor for the same reason.
    abandoned_flushes: u64,
    /// Messages delivered since the last settlement that could belong to a
    /// flush's output. A flush is settled between messages, never mid-burst: an
    /// upstream that was already quiet when the `Flush` went out has not answered
    /// it yet, and a batch pipelined behind a slow `Q` must not be settled by
    /// that `Q`'s own answer — which is why a delivered sync point resets this.
    fresh: u64,
    /// The tag of the most recently delivered message.
    last_tag: u8,
    /// The transaction status carried by the last `ReadyForQuery` delivered.
    ///
    /// A refusal echoes it instead of always claiming idle — after an allowed
    /// `BEGIN` the upstream really is in a transaction, and a driver told
    /// otherwise makes transaction-bound decisions on a wrong state. Relay-local
    /// because the relay is both the task that sees every `ReadyForQuery` and the
    /// task that writes the refusal.
    tx_status: u8,
}

impl Relay {
    fn new(client: tokio::net::tcp::OwnedWriteHalf, forwarded: Arc<Forwarded>) -> Self {
        Self {
            client,
            forwarded,
            queued: None,
            forced: false,
            stall_deadline: None,
            injections_closed: false,
            answered: 0,
            abandoned: 0,
            drained: 0,
            abandoned_flushes: 0,
            fresh: 0,
            last_tag: 0,
            tx_status: STATUS_IDLE,
        }
    }

    /// Whether the client has received everything it was owed when `refusal` was
    /// decided.
    ///
    /// Both counts must be satisfied: a session can owe the client a
    /// `ReadyForQuery` for a statement it synced and the output of a batch it
    /// only flushed, and either one arriving after the refusal is the
    /// misattribution this barrier exists to prevent.
    fn releasable(&self, refusal: &Refusal) -> bool {
        self.answered.max(self.abandoned) >= refusal.sync_points
            && self.drained.max(self.abandoned_flushes) >= refusal.flushes
    }

    /// Arm the stall bound for the queued answer.
    fn arm_stall(&mut self) {
        self.stall_deadline = Some(tokio::time::Instant::now() + REFUSAL_ORDER_STALL_TIMEOUT);
    }

    /// The deadline the queued answer's own caller set on being ordered, if any.
    fn order_deadline(&self) -> Option<tokio::time::Instant> {
        match &self.queued.as_ref()?.what {
            Injection::Refusal(refusal) => refusal.order_deadline,
            Injection::NoEncryption => None,
        }
    }

    /// Give up on ordering the queued refusal: not one byte of any backend
    /// message for a whole window means the missing answers are not late, they
    /// are not coming.
    ///
    /// Recorded as a floor rather than as a credit to what was delivered. The
    /// floor is compared against each refusal's own tag, so it releases exactly
    /// what a credit plus its debt released and nothing more: a statement
    /// forwarded after the write-off carries a higher tag, and is still ordered
    /// behind its own answer.
    fn give_up(&mut self) {
        let Some(Injected {
            what: Injection::Refusal(refusal),
            ..
        }) = &self.queued
        else {
            return;
        };
        let (sync_points, flushes) = (refusal.sync_points, refusal.flushes);
        // Both sides are reported, because either can be the one that stalled: a
        // refusal behind a `Flush`-driven batch can time out with its sync points
        // long since satisfied, and a warning carrying only those reads as though
        // nothing was outstanding at all.
        tracing::warn!(
            expected = sync_points,
            delivered = self.answered,
            expected_flushes = flushes,
            drained = self.drained,
            "no database response for the whole stall window; the refusal may reach the \
             client out of statement order"
        );
        self.abandoned = self.abandoned.max(sync_points);
        self.abandoned_flushes = self.abandoned_flushes.max(flushes);
    }

    /// Record that the relay has drained the output of **one** `Flush`, never
    /// past the `owed` value the caller read from [`Forwarded::flushes`].
    ///
    /// Called when the relay has delivered at least one message a flush could
    /// have produced and then found the upstream socket empty at a message
    /// boundary — the closest thing a `Flush` has to the `ReadyForQuery` that
    /// ends a request cycle.
    ///
    /// It is closer than "the first message delivered", which is what the counter
    /// alone would give: the whole of a flushed batch normally reaches the relay
    /// as one burst, so releasing on its first message leaves the refusal racing
    /// the rest of the burst.
    ///
    /// # Why one, and not every flush outstanding
    ///
    /// A quiet upstream cannot say *how many* flushes it drained, and the two
    /// readings fail in opposite directions. Crediting every outstanding flush
    /// is wrong for a client that flushes mid-batch — `Parse`/`Bind`/`Flush`/
    /// `Execute`/`Flush`, which is what `PQsendFlushRequest` exists for: the
    /// backend emits `ParseComplete` and `BindComplete` for the first flush and
    /// then goes quiet while it computes the `Execute`, and crediting both
    /// flushes there releases the refusal ahead of the rows. That is #101,
    /// reached through the fix for #113.
    ///
    /// Crediting one is wrong the other way, and only when two batches' output
    /// reaches the relay as a single uninterrupted burst: the second flush is
    /// left unsettled and the next refusal pays one
    /// [`REFUSAL_ORDER_STALL_TIMEOUT`] before being given up on. That needs the
    /// backend to produce the second batch faster than the relay drains the
    /// first, which the work it has to do between them makes unlikely — but
    /// unlikely is not the reason to choose it. The reason is the rule this
    /// barrier is already built on, stated in ADR-0007: the ambiguity is
    /// resolved toward waiting, because the failure there is latency and the
    /// failure the other way is ordering.
    ///
    /// It is still not exact even so. A burst split across TCP segments can
    /// leave the socket momentarily empty part-way through one batch's output,
    /// and a quiet read there settles that batch early. Closing it needs the
    /// relay to wait out a grace period on every quiet — a second timing
    /// constant, and a latency floor under every flush-driven refusal. That is
    /// a mechanism rather than a tweak, so it is recorded rather than taken
    /// here.
    fn flush_drained(&mut self, owed: u64) {
        if self.drained < owed {
            self.drained += 1;
        }
    }

    /// Record one complete backend message written to the client.
    ///
    /// Every message counts as progress and restarts the stall window; only a
    /// `ReadyForQuery` advances what a refusal is waiting for.
    fn delivered(&mut self, tag: u8) {
        self.last_tag = tag;
        if tag == b'Z' {
            // Settle the flushes this answer speaks for. The client has their
            // output either way, and a `ReadyForQuery` is a stronger settlement
            // than the quiet the relay would otherwise wait for. Bounded by the
            // snapshot taken when the sync point went out, so a `Flush` sent
            // after it is not credited here.
            let covered = self.forwarded.flushes_covered.load(Ordering::Relaxed);
            self.drained = self.drained.max(covered);
            // Never count past what was forwarded. In ordinary operation this
            // cannot bind — every `ReadyForQuery` answers a sync point counted
            // before the frame that earns it goes out — so it stands as a guard
            // against a backend that sends more of them than it was asked for,
            // not as part of the arithmetic.
            if self.answered < self.forwarded.sync_points.load(Ordering::Relaxed) {
                self.answered += 1;
            }
            // A request cycle just ended, so everything delivered so far is
            // accounted for by the sync-point count. Anything a still-unsettled
            // `Flush` is owed comes after this, not before it.
            self.fresh = 0;
        } else {
            self.fresh += 1;
        }
        if self.queued.is_some() {
            self.arm_stall();
        }
    }

    /// Write the queued injection if it may go out now, and acknowledge it.
    ///
    /// Called only between complete backend messages, which is what makes
    /// framing structural: there is no point in the relay's loop where this runs
    /// with part of a server frame already on the client's socket.
    async fn write_queued(&mut self) -> Result<(), Stop> {
        let ready = match self.queued.as_ref().map(|queued| &queued.what) {
            None => false,
            Some(Injection::NoEncryption) => true,
            Some(Injection::Refusal(refusal)) => self.forced || self.releasable(refusal),
        };
        if !ready {
            return Ok(());
        }
        let injected = self.queued.take().expect("checked just above");
        self.forced = false;
        self.stall_deadline = None;
        let written = match &injected.what {
            Injection::NoEncryption => self.client.write_all(b"N").await,
            Injection::Refusal(refusal) => self.write_refusal(&refusal.message).await,
        };
        if written.is_err() {
            return Err(Stop::Client);
        }
        // Dropped rather than sent when the caller has already gone, which costs
        // nothing: the answer is on the client's socket either way.
        let _ = injected.written.send(());
        Ok(())
    }

    /// Write the `ErrorResponse`/`ReadyForQuery` pair, echoing the transaction
    /// status of the last `ReadyForQuery` the client received.
    async fn write_refusal(&mut self, message: &str) -> std::io::Result<()> {
        self.client.write_all(&error_response(message)).await?;
        self.client
            .write_all(&[b'Z', 0, 0, 0, 5, self.tx_status])
            .await
    }

    /// Whether another injection may be taken off the channel.
    fn accepting(&self) -> bool {
        !self.injections_closed && self.queued.is_none()
    }

    /// Read `buf` full from the upstream, writing queued answers and honouring
    /// their bounds while it waits.
    ///
    /// Cancel-safe by construction: each arm does one `read` into the unfilled
    /// tail, so an arm that loses the race has taken nothing off the socket.
    /// `read_exact` would not do — cancelled part-way it drops the bytes it
    /// already consumed, and the client's stream is then unframed for the rest of
    /// the session.
    ///
    /// Nothing of the message being read has been written yet, so writing an
    /// answer from in here is still writing it between two complete backend
    /// messages.
    async fn fill<U>(
        &mut self,
        upstream: &mut U,
        injections: &mut mpsc::Receiver<Injected>,
        buf: &mut [u8],
        mut filled: usize,
    ) -> Result<(), Stop>
    where
        U: AsyncRead + Unpin,
    {
        while filled < buf.len() {
            let stall = self.stall_deadline;
            let order = self.order_deadline();
            tokio::select! {
                // The channel first. A refusal the message loop has decided
                // belongs *before* whatever the database is about to send — it
                // was decided before that frame was requested — and picking
                // between the two at random is the reordering the barrier exists
                // to prevent.
                biased;
                taken = injections.recv(), if self.accepting() => match taken {
                    Some(injected) => {
                        self.queued = Some(injected);
                        self.arm_stall();
                        self.write_queued().await?;
                    }
                    // The inspected direction has ended, so nothing more will be
                    // injected — but the database may still owe the client its
                    // last response, so the relay keeps relaying.
                    None => self.injections_closed = true,
                },
                () = until(stall) => {
                    self.give_up();
                    self.forced = true;
                    self.write_queued().await?;
                }
                () = until(order) => {
                    // The caller budgeted ordering and writing apart and its
                    // ordering slice is spent. Nothing is written off: this is
                    // one answer giving up its place, not the pipeline being
                    // declared dead.
                    self.forced = true;
                    self.write_queued().await?;
                }
                read = upstream.read(&mut buf[filled..]) => match read {
                    Ok(0) | Err(_) => return Err(Stop::Upstream),
                    Ok(read) => filled += read,
                },
            }
        }
        Ok(())
    }
}

/// Sleep until `deadline`, or never when there is none.
async fn until(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
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

    let forwarded = Arc::new(Forwarded::new());
    let (injections, taken) = mpsc::channel(1);
    let link = ClientLink {
        forwarded: Arc::clone(&forwarded),
        injections,
    };
    let mut downstream = tokio::spawn(upstream_to_client(
        upstream_read,
        client_write,
        taken,
        forwarded,
    ));

    let mut ended = ClientEnd::default();
    let outcome = tokio::select! {
        // Poll the message loop first. When the relay stops, both arms can become
        // ready in the same wake-up — and an unbiased `select!` would pick
        // between them at random, dropping the loop half the time before it has
        // learned that the answer it was about to ask for has to be written some
        // other way. Biased, the loop runs, discovers the channel closed, and
        // hands the unwritten answer back below. Nothing is starved: the arm
        // below is still reached the moment the loop is pending.
        biased;
        result = client_to_upstream(
            state,
            &mut client_read,
            &mut upstream_write,
            &link,
            &facts,
        ) => {
            if let Ok(end) = result {
                ended = end;
                Ok(())
            } else {
                result.map(|_| ())
            }
        }
        // Upstream closed (or the client's socket died under the relay): the
        // session is over in both directions.
        _ = &mut downstream => Ok(()),
    };

    // An answer the relay had already stopped for. It is written with the write
    // half the relay hands back — one owner at a time, never two — and only when
    // it hands one back at all, which it does not when a failed write left the
    // client holding a partial frame. Awaiting the handle cannot block here: the
    // only way the message loop learned the relay was gone is that the relay
    // dropped the channel on its way out.
    if let Some(message) = ended.unwritten {
        if let Ok(Some(mut relayed)) = (&mut downstream).await {
            let _ = relayed.client.write_all(&error_response(&message)).await;
            let _ = relayed
                .client
                .write_all(&[b'Z', 0, 0, 0, 5, relayed.tx_status])
                .await;
        }
    }

    // The client sent everything it had. Half-close the upstream write half so
    // the database sees the end of input and flushes whatever it still owes,
    // then let the relay deliver it. Aborting straight away instead would
    // truncate the response to a client that sent its last query and shut down
    // its write half before reading.
    if ended.drain {
        let _ = upstream_write.shutdown().await;
        // Dropping the link closes the injection channel, so the relay stops
        // waiting on a message loop that has finished.
        drop(link);
        let _ = tokio::time::timeout(DRAIN_TIMEOUT, &mut downstream).await;
    }
    downstream.abort();
    outcome
}

/// Relay upstream→client, one complete backend message at a time, and write the
/// answers honmoon generates itself in between.
///
/// This task owns the client write half for the whole session, which is what
/// puts framing and ordering in the one place that knows both. It hands the
/// writer back when it stops with the client's stream still framed — that is what
/// lets [`run_postgres`] answer a refusal decided after this task had already
/// stopped — and drops it otherwise.
async fn upstream_to_client<U>(
    upstream: U,
    client: tokio::net::tcp::OwnedWriteHalf,
    mut injections: mpsc::Receiver<Injected>,
    forwarded: Arc<Forwarded>,
) -> Option<HandBack>
where
    U: AsyncRead + TryRead + Unpin,
{
    let mut relay = Relay::new(client, forwarded);
    match relay_backend_messages(upstream, &mut relay, &mut injections).await {
        // No further `ReadyForQuery` can reach the client now, so nothing is left
        // to order the queued answer against: it goes out rather than being
        // dropped when this task ends, which is what keeps a client whose own
        // socket is fine from reading an unexplained close instead of its 42501.
        Stop::Upstream => {
            relay.forced = true;
            relay.write_queued().await.ok()?;
            Some(HandBack {
                client: relay.client,
                tx_status: relay.tx_status,
            })
        }
        // The client is holding a frame header whose payload never arrived, so
        // its stream is desynchronised and nothing honmoon writes can be read as
        // a message any more: an injected `ErrorResponse` would be consumed as
        // the rest of that frame. The writer is dropped with this task, so there
        // is nothing left that could add to the truncation.
        Stop::Client => None,
    }
}

/// The relay's message loop, split out so every way it can end reports where it
/// stopped to [`upstream_to_client`] above exactly once.
async fn relay_backend_messages<U>(
    mut upstream: U,
    relay: &mut Relay,
    injections: &mut mpsc::Receiver<Injected>,
) -> Stop
where
    U: AsyncRead + TryRead + Unpin,
{
    loop {
        // A flush is settled between messages, never mid-burst, and never after a
        // message that cannot be the *last* one a `Flush` pushes — because a
        // quiet there is a backend still working rather than one that has
        // finished:
        //
        // - `DataRow` / `CopyData`: an `Execute` ends on `CommandComplete`,
        //   `EmptyQueryResponse`, `PortalSuspended` or `ErrorResponse`, and a
        //   copy-out on `CopyDone`, so a pause here is mid-result-set;
        // - `NoticeResponse` / `NotificationResponse` / `ParameterStatus`: these
        //   are asynchronous and can be emitted *during* a statement — a
        //   function that raises a notice and then computes for a while flushes
        //   the notice and goes quiet with its `CommandComplete` still to come;
        // - `ParameterDescription` / `RowDescription`: a `Describe` of a
        //   statement answers with the first and then the second or `NoData`,
        //   and a `Bind`/`Describe`/`Execute` batch emits `RowDescription`
        //   before the first row — a backend that has planned the query and not
        //   yet produced a row pauses exactly there;
        // - `CopyInResponse` / `CopyOutResponse` / `CopyBothResponse` /
        //   `CopyDone`: each opens or punctuates a copy whose `CommandComplete`
        //   has not been sent.
        //
        // This is a list of what can never end a batch, not of what always
        // does: a terminal-looking message can still be mid-batch (two
        // `Execute`s under one `Flush` both end on `CommandComplete`), which
        // ADR-0007 records rather than claims to solve. The two ways of being
        // wrong are not equal, so the list errs toward not settling.
        let owed = relay.forwarded.flushes.load(Ordering::Relaxed);
        let settling = relay.fresh > 0
            && !matches!(
                relay.last_tag,
                b'D' | b'd' | b'N' | b'A' | b'S' | b't' | b'T' | b'G' | b'H' | b'W' | b'c'
            )
            && relay.drained < owed;

        // Every backend message is `tag(1) | len(4, self-inclusive) | payload`.
        //
        // When a flush is outstanding the head's first read is attempted without
        // waiting, so that "the upstream has nothing more right now" — the only
        // signal the wire carries that a `Flush`'s output is all delivered — is
        // read off the same operation that would have fetched the bytes. It
        // fetches them when there are any, and reports the quiet when there are
        // not.
        let mut head = [0u8; 5];
        let mut filled = 0usize;
        if settling {
            match upstream.try_read_now(&mut head) {
                Ok(0) => return Stop::Upstream,
                Ok(read) => filled = read,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    relay.fresh = 0;
                    relay.flush_drained(owed);
                }
                Err(_) => return Stop::Upstream,
            }
        }
        // What that settled may have released the queued answer, and the read
        // below blocks for as long as the database cares to take. Checking only
        // inside the read would leave the answer sitting behind a wait that
        // nothing is going to satisfy.
        if let Err(stop) = relay.write_queued().await {
            return stop;
        }

        if let Err(stop) = relay
            .fill(&mut upstream, injections, &mut head, filled)
            .await
        {
            return stop;
        }
        let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
        if len < 4 {
            // Malformed framing; the stream is no longer trustworthy. Nothing of
            // this message reached the client, so what it already has is whole.
            return Stop::Upstream;
        }
        let payload_len = len - 4;

        if payload_len > MAX_BUFFERED_BACKEND_MESSAGE {
            // Too large to hold in memory: written head-first and streamed. No
            // injection is considered from here until the copy is done — the
            // client is mid-frame for all of it, and this task is the only one
            // that could write into it.
            if relay.client.write_all(&head).await.is_err()
                || copy_exact(&mut upstream, &mut relay.client, payload_len)
                    .await
                    .is_err()
            {
                // The header may already be on the client's socket with only
                // part of its payload behind it — `write_all` can fail after a
                // partial write, and the copy fails mid-payload by definition.
                return Stop::Client;
            }
            // Oversized by construction, so never a `ReadyForQuery` (six bytes):
            // progress for the stall window, never a sync point.
            relay.delivered(head[0]);
            continue;
        }

        let mut payload = vec![0u8; payload_len];
        if let Err(stop) = relay.fill(&mut upstream, injections, &mut payload, 0).await {
            return stop;
        }
        // `ReadyForQuery` is the only message that states the transaction status.
        if head[0] == b'Z' && !payload.is_empty() {
            relay.tx_status = payload[0];
        }
        if relay.client.write_all(&head).await.is_err()
            || relay.client.write_all(&payload).await.is_err()
        {
            return Stop::Client;
        }
        // Counted only once the client really has the message: an answer
        // released mid-write would overtake the very response it waited for.
        relay.delivered(head[0]);
    }
}

/// How the inspected direction of a session ended.
#[derive(Default)]
struct ClientEnd {
    /// `true` only for a *clean* end of the client's stream after its traffic
    /// reached the upstream, so the database may still owe a response and the
    /// caller should drain. `false` when nothing is owed: the session ended
    /// during startup (a relayed `CancelRequest`, an unrecognized packet, or a
    /// client that left before negotiating), the connection was reset mid-
    /// session, or the client left while a statement of its was held for
    /// approval — in none of which is anyone left to read the last response.
    drain: bool,
    /// A refusal the relay had already stopped for, so it could not be written
    /// through the channel.
    ///
    /// Carried out rather than written here: the relay owns the client writer for
    /// the whole session and hands it back only when the client's stream is still
    /// framed, so [`run_postgres`] writes this on a stream that can read it as a
    /// message — or nothing writes it at all.
    unwritten: Option<String>,
}

impl ClientEnd {
    /// The session ends here, owing the client one answer the relay could not
    /// take. Nothing is drained: the relay is gone, so the database has no way to
    /// reach the client even if it does still owe a response.
    fn unwritten(message: String) -> Self {
        Self {
            drain: false,
            unwritten: Some(message),
        }
    }
}

/// Drive the inspected direction: startup negotiation, then the message loop.
async fn client_to_upstream<R, W>(
    state: &GatewayState,
    client: &mut R,
    upstream: &mut W,
    link: &ClientLink,
    facts: &Facts,
) -> std::io::Result<ClientEnd>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if !startup(client, upstream, link).await? {
        return Ok(ClientEnd::default());
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
                // Written by the relay like everything else honmoon sends the
                // client. A relay that cannot write it is a session with no
                // client left to negotiate with.
                if link.inject(Injection::NoEncryption).await.is_err() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "the client write half is gone",
                    ));
                }
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
    /// Refuse it with this message, and go on with the session.
    Refuse(String),
    /// The client left while its statement was held for approval. Nothing may
    /// be forwarded on its behalf and there is nobody to answer, so the session
    /// ends here.
    ClientGone,
}

/// Frame the client's messages and decide the ones that carry SQL.
async fn message_loop<R, W>(
    state: &GatewayState,
    client: &mut R,
    upstream: &mut W,
    link: &ClientLink,
    facts: &Facts,
) -> std::io::Result<ClientEnd>
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
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(ClientEnd {
                    drain: true,
                    unwritten: None,
                });
            }
            // A reset or aborted connection. Nobody is left to read the last
            // response, so draining would just hold an upstream connection and
            // a task open for `DRAIN_TIMEOUT` — which a client can repeat until
            // the connection cap is exhausted.
            Err(_) => return Ok(ClientEnd::default()),
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
            } else if tag[0] == b'H' {
                // `Flush` ends no request cycle and earns no `ReadyForQuery`,
                // but it is what makes the batch before it reach the client, so
                // it is what a refusal behind that batch has to wait for. Its
                // own counter, settled by the relay rather than by a sync point
                // (#113).
                link.forwarded_flush();
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
            if let Some(end) = refuse_uninspectable(
                state,
                facts,
                link,
                "honmoon: query frame exceeds inspection cap",
            )
            .await
            {
                return Ok(end);
            }
            continue;
        }

        let mut payload = vec![0u8; payload_len];
        client_reader.read_exact(&mut payload).await?;

        // A simple query may legally carry several statements, but `parse_sql`
        // only ever sees the first verb — `SELECT 1; DROP TABLE users` would be
        // decided as a `SELECT` and forwarded whole. Nothing downstream re-reads
        // the rest, so the frame is refused rather than forwarded uninspected.
        if tag[0] == b'Q' && payload_carries_multiple_statements(&payload) {
            if let Some(end) = refuse_uninspectable(
                state,
                facts,
                link,
                "honmoon: multi-statement query frames are not inspectable",
            )
            .await
            {
                return Ok(end);
            }
            continue;
        }

        // A `DO` block runs an arbitrary PL/pgSQL body while reporting the
        // harmless verb `DO`, and the body is not SQL, so there is nothing to
        // classify — the statements inside it are simply unreachable. Refuse the
        // frame, the same fail-closed answer a batch gets. Unlike the batch
        // check this applies to `P` as well as `Q`: a `DO` block can be prepared.
        if frame_query(tag[0], &payload).is_some_and(is_uninspectable_statement) {
            if let Some(end) =
                refuse_uninspectable(state, facts, link, "honmoon: DO blocks are not inspectable")
                    .await
            {
                return Ok(end);
            }
            continue;
        }

        let Some(sql) = statement_facts(tag[0], &len_bytes, &payload) else {
            // A `Q`/`P` frame we cannot parse is refused rather than forwarded
            // blind — the same fail-closed posture as the frame cap, and it is
            // audited the same way, so every refusal leaves a trail.
            if let Some(end) =
                refuse_uninspectable(state, facts, link, "honmoon: unparseable query frame").await
            {
                return Ok(end);
            }
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
            Disposition::Refuse(message) => {
                if refuse(link, &message).await.is_err() {
                    return Ok(ClientEnd::unwritten(message));
                }
            }
            // No drain: the client that would have read the answer is gone.
            Disposition::ClientGone => return Ok(ClientEnd::default()),
        }
    }
}

/// Audit and refuse one frame the runtime could not inspect.
///
/// Returns how the session ends when the relay could not write the answer, and
/// `None` when the session goes on — which it does for every refusal the client
/// is actually told about, per ADR-0007.
async fn refuse_uninspectable(
    state: &GatewayState,
    facts: &Facts,
    link: &ClientLink,
    message: &str,
) -> Option<ClientEnd> {
    record(state, facts, None, Decision::Denied, Verdict::Deny);
    refuse(link, message)
        .await
        .err()
        .map(|Unwritten| ClientEnd::unwritten(message.to_owned()))
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
                    // that really left just makes the relay's write fail,
                    // harmlessly.
                    //
                    // Bounded twice over. The outer budget ends the session even
                    // if the answer never reaches a client that half-closed and
                    // stopped reading, which would otherwise leave the relay
                    // blocked on a full send buffer for good. The inner one is
                    // the slice of it this answer may spend being *ordered*: the
                    // same half-close that ended the hold is what stalls the
                    // pipeline, so spending the whole budget on the wait would
                    // leave nothing for the answer itself.
                    let ordered_by = tokio::time::Instant::now() + ABANDONED_NOTICE_ORDER_BUDGET;
                    let _ = tokio::time::timeout(
                        ABANDONED_NOTICE_TIMEOUT,
                        link.inject(Injection::Refusal(link.refusal(
                            "honmoon: connection ended while the statement was held for approval",
                            Some(ordered_by),
                        ))),
                    )
                    .await;
                    return Ok(Disposition::ClientGone);
                }
                HoldOutcome::Rejected | HoldOutcome::QueueFull => false,
            }
        }
    };

    if !allowed {
        return Ok(Disposition::Refuse(denial_message(outcome.rule.as_deref())));
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
/// The answer is written by the relay, in PostgreSQL request order: it is tagged
/// with what the client was owed when the refusal was decided, and the relay
/// holds it until it has delivered that much — so a client that pipelined
/// `SELECT pg_sleep(1); DROP TABLE users;` reads the `SELECT`'s response first
/// and attributes the `42501` to the statement it belongs to.
///
/// `Err` means the relay could not write it: it has stopped, or its writer is
/// gone because the client's stream is no longer framed.
async fn refuse(link: &ClientLink, message: &str) -> Result<(), Unwritten> {
    link.inject(Injection::Refusal(link.refusal(message, None)))
        .await
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

    /// A connected loopback pair: the end a test drives, and the end handed to
    /// the code under test.
    async fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (near, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (near.unwrap(), accepted.unwrap().0)
    }

    /// A session's plumbing over real loopback sockets: the link a message loop
    /// writes through, the relay running in its own task with the only client
    /// write half there is, the end of the client connection a test reads
    /// honmoon's answers from, and the end of the upstream connection a test
    /// writes backend messages to.
    ///
    /// Writing a backend message to `database` is how a test decides *when* the
    /// client is answered. The writer is a concrete `OwnedWriteHalf`, so the
    /// ordering is asserted on bytes a client really read and not on an
    /// in-memory stand-in.
    struct Session {
        link: ClientLink,
        client: TcpStream,
        database: TcpStream,
        _relay: tokio::task::JoinHandle<Option<HandBack>>,
    }

    async fn session() -> Session {
        let (client, client_end) = socket_pair().await;
        let (upstream_end, database) = socket_pair().await;
        // Only the halves the runtime uses are kept: the relay reads the upstream
        // and writes the client, and dropping the other two just half-closes
        // directions these tests do not drive.
        let (_client_read, client_write) = client_end.into_split();
        let (upstream_read, _upstream_write) = upstream_end.into_split();
        let forwarded = Arc::new(Forwarded::new());
        let (injections, taken) = mpsc::channel(1);
        let link = ClientLink {
            forwarded: Arc::clone(&forwarded),
            injections,
        };
        let _relay = tokio::spawn(upstream_to_client(
            upstream_read,
            client_write,
            taken,
            forwarded,
        ));
        Session {
            link,
            client,
            database,
            _relay,
        }
    }

    /// Hand a refusal to the relay exactly as [`refuse`] does, returning the
    /// acknowledgement the message loop would wait on.
    ///
    /// Tests that have no message loop use this to ask "would honmoon's answer go
    /// out now?" — and unlike a peek at a counter, the answer is that the bytes
    /// really reached the client.
    fn queue_refusal(link: &ClientLink, message: &str) -> oneshot::Receiver<()> {
        let (written, ack) = oneshot::channel();
        link.injections
            .try_send(Injected {
                what: Injection::Refusal(link.refusal(message, None)),
                written,
            })
            .expect("the channel holds one and nothing else has filled it");
        ack
    }

    /// The relay's accounting with no upstream attached: the counters a message
    /// loop raises, and the relay that decides when an answer tagged with them
    /// may go out.
    ///
    /// Used where the question is the arithmetic itself rather than what a client
    /// reads — the cases that used to be asserted against `Delivered`'s fields.
    struct Accounting {
        relay: Relay,
        link: ClientLink,
        /// Kept alive so the relay's writer has a peer and the channel a receiver.
        taken: mpsc::Receiver<Injected>,
        _peer: TcpStream,
    }

    async fn accounting() -> Accounting {
        let (peer, honmoon_end) = socket_pair().await;
        let (_read, client_write) = honmoon_end.into_split();
        let forwarded = Arc::new(Forwarded::new());
        let (injections, taken) = mpsc::channel(1);
        Accounting {
            relay: Relay::new(client_write, Arc::clone(&forwarded)),
            link: ClientLink {
                forwarded,
                injections,
            },
            taken,
            _peer: peer,
        }
    }

    impl Accounting {
        /// What a refusal decided right now would be tagged with.
        fn refusal(&self) -> Refusal {
            self.link.refusal("honmoon: denied by policy", None)
        }

        /// Whether an answer tagged for right now could be written right now.
        fn releasable_now(&self) -> bool {
            self.relay.releasable(&self.refusal())
        }

        /// Give up on ordering a refusal decided right now, the way the stall
        /// bound does, and clear it as writing it would.
        fn abandon(&mut self) {
            let (written, _ack) = oneshot::channel();
            self.relay.queued = Some(Injected {
                what: Injection::Refusal(self.refusal()),
                written,
            });
            self.relay.give_up();
            self.relay.queued = None;
            self.relay.stall_deadline = None;
        }

        /// Settle one flush the way the relay does on a quiet upstream.
        fn quiet(&mut self) {
            let owed = self.link.forwarded.flushes.load(Ordering::Relaxed);
            self.relay.flush_drained(owed);
        }
    }

    /// An upstream that yields scripted chunks after scripted quiet periods and
    /// has nothing available in between. An empty chunk is end of input.
    ///
    /// No socket, deliberately. A paused clock jumps to the next timer deadline
    /// while a real socket's readiness is still in flight, so the tests that
    /// assert the stall bound is *not* reached cannot have one — which is why the
    /// relay reads through [`TryRead`] rather than the concrete half.
    struct ScriptedUpstream {
        script: std::collections::VecDeque<(std::time::Duration, Vec<u8>)>,
        /// The chunk being handed out.
        ready: std::io::Cursor<Vec<u8>>,
        /// The quiet period currently being waited out.
        quiet: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    }

    impl ScriptedUpstream {
        fn new<I>(script: I) -> Self
        where
            I: IntoIterator<Item = (std::time::Duration, Vec<u8>)>,
        {
            Self {
                script: script.into_iter().collect(),
                ready: std::io::Cursor::new(Vec::new()),
                quiet: None,
            }
        }

        fn buffered(&self) -> usize {
            self.ready.get_ref().len() - self.ready.position() as usize
        }
    }

    impl AsyncRead for ScriptedUpstream {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let me = &mut *self;
            if me.buffered() > 0 {
                return std::pin::Pin::new(&mut me.ready).poll_read(cx, buf);
            }
            let Some((quiet, _)) = me.script.front() else {
                return std::task::Poll::Pending;
            };
            let quiet = *quiet;
            let sleep = me
                .quiet
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(quiet)));
            if std::future::Future::poll(sleep.as_mut(), cx).is_pending() {
                return std::task::Poll::Pending;
            }
            me.quiet = None;
            let (_, chunk) = me.script.pop_front().expect("checked just above");
            me.ready = std::io::Cursor::new(chunk);
            std::pin::Pin::new(&mut me.ready).poll_read(cx, buf)
        }
    }

    impl TryRead for ScriptedUpstream {
        fn try_read_now(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let buffered = self.buffered();
            if buffered == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            let take = buffered.min(buf.len());
            let at = self.ready.position() as usize;
            buf[..take].copy_from_slice(&self.ready.get_ref()[at..at + take]);
            self.ready.set_position((at + take) as u64);
            Ok(take)
        }
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

    /// A policy that holds every `DELETE` for a human.
    fn pause_delete_policy() -> honmoon_core::Policy {
        honmoon_core::Policy::from_yaml(
            "egress:\n  default: allow\nrules:\n  - name: review-delete\n    endpoint: '*'\n    condition: \"sql.verb == 'DELETE'\"\n    verdict: pause\n",
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

    /// `CommandComplete` for a statement that returned one row.
    fn command_complete() -> Vec<u8> {
        let tag = b"SELECT 1\0";
        let mut done = vec![b'C'];
        done.extend_from_slice(&((4 + tag.len()) as u32).to_be_bytes());
        done.extend_from_slice(tag);
        done
    }

    /// A `Q` frame carrying `sql`, as the client puts it on the wire.
    fn simple_query(sql: &str) -> Vec<u8> {
        let mut frame = vec![b'Q'];
        frame.extend_from_slice(&((5 + sql.len()) as u32).to_be_bytes());
        frame.extend_from_slice(sql.as_bytes());
        frame.push(0);
        frame
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

    fn parse_payload(name: &str, query: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(name.as_bytes());
        payload.push(0);
        payload.extend_from_slice(query.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&0i16.to_be_bytes()); // no parameter types
        payload
    }

    /// A `Q` payload is the query text plus its NUL terminator.
    fn q_payload(query: &str) -> Vec<u8> {
        let mut payload = Vec::from(query.as_bytes());
        payload.push(0);
        payload
    }

    fn startup_packet(code: u32, body: &[u8]) -> Vec<u8> {
        let len = 8 + body.len();
        let mut packet = Vec::with_capacity(len);
        packet.extend_from_slice(&(len as u32).to_be_bytes());
        packet.extend_from_slice(&code.to_be_bytes());
        packet.extend_from_slice(body);
        packet
    }

    /// The `Bind`/`Execute`/`Flush` tail of an extended-protocol batch driven
    /// the way a pipelining client drives it: no `Sync`, so the database answers
    /// with the output the `Flush` pushes and no `ReadyForQuery` at all.
    fn flush_driven_batch(name: &str) -> Vec<u8> {
        // `Bind`: unnamed portal, named statement, no formats and no parameters.
        let mut bind_payload = vec![0u8];
        bind_payload.extend_from_slice(name.as_bytes());
        bind_payload.push(0);
        bind_payload.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        let mut frames = vec![b'B'];
        frames.extend_from_slice(&((4 + bind_payload.len()) as u32).to_be_bytes());
        frames.extend_from_slice(&bind_payload);
        // `Execute`: unnamed portal, no row limit.
        frames.extend_from_slice(&[b'E', 0, 0, 0, 9, 0, 0, 0, 0, 0]);
        // `Flush`: the whole point — it earns no `ReadyForQuery`.
        frames.extend_from_slice(&[b'H', 0, 0, 0, 4]);
        frames
    }

    /// What a database answers a flushed batch with: `ParseComplete`,
    /// `BindComplete`, `CommandComplete` — and no `ReadyForQuery`.
    fn flushed_batch_response() -> Vec<u8> {
        let mut frames = vec![b'1', 0, 0, 0, 4, b'2', 0, 0, 0, 4];
        frames.extend_from_slice(&command_complete());
        frames
    }

    #[tokio::test]
    async fn a_session_that_never_leaves_startup_does_not_ask_for_a_drain() {
        let state = GatewayState::new(honmoon_core::Policy::default());
        let mut client = std::io::Cursor::new(startup_packet(0xDEAD_BEEF, b""));
        let mut upstream: Vec<u8> = Vec::new();
        let session = session().await;

        let ended = client_to_upstream(
            &state,
            &mut client,
            &mut upstream,
            &session.link,
            &Facts::default(),
        )
        .await
        .unwrap();

        assert!(
            !ended.drain,
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
        let session = session().await;

        let ended = client_to_upstream(
            &state,
            &mut client,
            &mut upstream,
            &session.link,
            &Facts::default(),
        )
        .await
        .unwrap();

        assert!(
            !ended.drain,
            "a reset connection is not a clean end of input"
        );
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
        let session = session().await;

        let ended = client_to_upstream(
            &state,
            &mut client,
            &mut upstream,
            &session.link,
            &Facts::default(),
        )
        .await
        .unwrap();

        assert!(
            ended.drain,
            "the startup packet reached the upstream, so its response must still be drained"
        );
    }

    #[tokio::test]
    async fn encryption_is_refused_by_the_relay_like_every_other_local_answer() {
        // The `N` that refuses `SSLRequest` is the one thing honmoon writes to
        // the client before the session has begun, and it goes through the same
        // channel as a refusal — because there is only one writer, for the whole
        // session, from the first byte.
        let state = GatewayState::new(honmoon_core::Policy::default());
        let mut frames = startup_packet(SSL_REQUEST, b"");
        frames.extend_from_slice(&startup_packet(PROTOCOL_V3, b"user\0me\0\0"));
        let mut client = std::io::Cursor::new(frames);
        let mut upstream: Vec<u8> = Vec::new();
        let mut session = session().await;

        let ended = client_to_upstream(
            &state,
            &mut client,
            &mut upstream,
            &session.link,
            &Facts::default(),
        )
        .await
        .unwrap();

        assert!(ended.drain, "the StartupMessage reached the upstream");
        let mut answered = [0u8; 1];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            session.client.read_exact(&mut answered),
        )
        .await
        .expect("the client is answered")
        .expect("the client is answered");
        assert_eq!(&answered, b"N", "encryption is refused, in plain sight");
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
        let mut session = session().await;

        let ended = message_loop(
            &state,
            &mut client,
            &mut upstream,
            &session.link,
            &Facts::default(),
        )
        .await
        .unwrap();

        assert!(
            upstream.is_empty(),
            "a statement whose client is gone must never reach the database"
        );
        assert!(
            !ended.drain,
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
        session
            .client
            .read_exact(&mut answer)
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
        let mut session = session().await;

        let facts = Facts::default();
        let loop_run = message_loop(&state, &mut client, &mut upstream, &session.link, &facts);
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
            session.client.read_exact(&mut answer),
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

    #[tokio::test]
    async fn a_refusal_waits_for_the_response_to_a_statement_already_forwarded() {
        let state = GatewayState::new(deny_drop_policy());
        // The `SELECT` is forwarded and the database is still working on it when
        // the `DROP` is refused. Injecting straight away would put honmoon's
        // 42501 in front of the `SELECT`'s response, and the client would
        // attribute the error to the statement it already had answered (#101).
        let mut client = std::io::Cursor::new(pipelined_select_then_drop());
        let mut upstream: Vec<u8> = Vec::new();
        let Session {
            link,
            client: mut peer,
            mut database,
            _relay,
        } = session().await;

        let facts = Facts::default();
        let run = message_loop(&state, &mut client, &mut upstream, &link, &facts);
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

        let (ended, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(run, client_view)
        })
        .await
        .expect("the session finished");
        assert!(
            ended.unwrap().drain,
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
        // The answers that never came are then recorded as given up on — a
        // refusal is released once *either* count reaches its tag — so the
        // *second* `DROP` does not pay the same window again, and nor does any
        // refusal after it for the whole session.
        let mut frames = pipelined_select_then_drop();
        frames.extend_from_slice(&simple_query("DROP TABLE accounts"));
        let mut client = std::io::Cursor::new(frames);
        let mut upstream: Vec<u8> = Vec::new();
        let Session {
            link,
            client: mut peer,
            database: _database,
            _relay,
        } = session().await;

        let started = tokio::time::Instant::now();
        let facts = Facts::default();
        let run = message_loop(&state, &mut client, &mut upstream, &link, &facts);
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

        let (ended, ()) = tokio::join!(run, client_view);
        assert!(
            ended.unwrap().drain,
            "the session survives the late refusals"
        );
        assert_eq!(
            started.elapsed(),
            REFUSAL_ORDER_STALL_TIMEOUT,
            "one stall window for the whole session, not one per refusal"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_sync_swallowed_during_copy_in_still_lets_the_queued_refusal_out() {
        // PostgreSQL ignores `Flush` and `Sync` received during copy-in mode, so
        // a `Sync` forwarded there is counted and can never be answered: the
        // forwarded count is permanently one ahead of what the backend will
        // answer. The bound lives inside the relay for exactly this — without it
        // the relay never reaches the tag, the refusal is never dequeued, and the
        // client hangs on a 42501 that is never written, which is worse than the
        // out-of-order refusal #101 fixed.
        //
        // The recurring latency this leaves behind is #128 and is not touched
        // here; what this pins is that it stays latency and never a hang.
        let mut acc = accounting().await;
        // The `COPY` statement and the `Sync` the client sent behind it: two sync
        // points forwarded, and the backend answers neither.
        acc.link.forwarded_sync_point();
        acc.link.forwarded_sync_point();
        let copy_in_response = vec![b'G', 0, 0, 0, 7, 0, 0, 0];
        let upstream = ScriptedUpstream::new([
            (std::time::Duration::ZERO, copy_in_response),
            (REFUSAL_ORDER_STALL_TIMEOUT * 2, Vec::new()),
        ]);

        let ack = queue_refusal(&acc.link, "honmoon: denied by policy");
        let started = tokio::time::Instant::now();
        let written = async {
            ack.await.expect("the refusal is written");
            tokio::time::Instant::now()
        };
        let (_stop, written_at) = tokio::join!(
            relay_backend_messages(upstream, &mut acc.relay, &mut acc.taken),
            written,
        );

        assert_eq!(
            written_at - started,
            REFUSAL_ORDER_STALL_TIMEOUT,
            "bounded by the stall window, not unbounded"
        );
        assert_eq!(
            acc.relay.answered, 0,
            "the backend answered neither sync point, `CopyInResponse` and all"
        );
        assert_eq!(
            acc.relay.abandoned, 2,
            "both were given up on at once, so no later refusal on the session pays again"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_pipeline_that_keeps_moving_never_hits_the_stall_bound() {
        // The bound is on the stall, not on the wait. Two answers are owed and
        // each arrives just inside a window, so every delivery buys another one
        // and the refusal is written on the second `ReadyForQuery` instead of on
        // the bound — a database working steadily through a statement that
        // outlives one window is ordered properly rather than cut off.
        //
        // Driven over a scripted upstream rather than a socket: a paused clock
        // jumps to the stall deadline while a real socket's readiness is still in
        // flight, and the test would measure the bound it is meant to prove is
        // not reached.
        let mut acc = accounting().await;
        acc.link.forwarded_sync_point();
        acc.link.forwarded_sync_point();
        let step = REFUSAL_ORDER_STALL_TIMEOUT - std::time::Duration::from_secs(5);
        let ready_for_query = vec![b'Z', 0, 0, 0, 5, b'I'];
        let upstream = ScriptedUpstream::new([
            (step, ready_for_query.clone()),
            (step, ready_for_query),
            (std::time::Duration::ZERO, Vec::new()),
        ]);

        let ack = queue_refusal(&acc.link, "honmoon: denied by policy");
        let started = tokio::time::Instant::now();
        let written = async {
            ack.await.expect("the refusal is written");
            tokio::time::Instant::now()
        };
        let (stop, written_at) = tokio::join!(
            relay_backend_messages(upstream, &mut acc.relay, &mut acc.taken),
            written,
        );

        assert!(matches!(stop, Stop::Upstream));
        assert_eq!(
            written_at - started,
            2 * step,
            "the wait ended on the last answer, not on the stall bound"
        );
        assert_eq!(
            acc.relay.abandoned, 0,
            "nothing was given up on — every answer arrived"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn rows_streaming_out_of_a_slow_query_hold_the_stall_window_open() {
        // Only `ReadyForQuery` advances what a refusal waits *for*, but every
        // backend message is progress. A query streaming `DataRow`s for longer
        // than the window is a database working, not one that stopped — and
        // treating it as stopped would inject the refusal into the middle of
        // that result set, which is worse than the misattribution #101 removed.
        let mut acc = accounting().await;
        acc.link.forwarded_sync_point();
        let step = REFUSAL_ORDER_STALL_TIMEOUT - std::time::Duration::from_secs(5);
        let row = vec![b'D', 0, 0, 0, 11, 0, 1, 0, 0, 0, 1, b'x'];
        let upstream = ScriptedUpstream::new([
            (step, row.clone()),
            (step, row),
            (step, vec![b'Z', 0, 0, 0, 5, b'I']),
            (std::time::Duration::ZERO, Vec::new()),
        ]);

        let ack = queue_refusal(&acc.link, "honmoon: denied by policy");
        let started = tokio::time::Instant::now();
        let written = async {
            ack.await.expect("the refusal is written");
            tokio::time::Instant::now()
        };
        let (_stop, written_at) = tokio::join!(
            relay_backend_messages(upstream, &mut acc.relay, &mut acc.taken),
            written,
        );

        assert_eq!(written_at - started, 3 * step, "rows counted as progress");
        assert_eq!(
            acc.relay.abandoned, 0,
            "a working database is never given up on"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_flush_the_database_never_answers_costs_one_stall_window() {
        // The bound has to survive the flush counter too: a `Flush` that elicits
        // nothing — sent with no pending output, or ignored because a `COPY` is
        // in progress — is never settled by the relay, and without the bound that
        // turns an ordering bug into a hang.
        let mut acc = accounting().await;
        acc.link.forwarded_flush();
        let upstream = ScriptedUpstream::new([(REFUSAL_ORDER_STALL_TIMEOUT * 2, Vec::new())]);

        let ack = queue_refusal(&acc.link, "honmoon: denied by policy");
        let started = tokio::time::Instant::now();
        let written = async {
            ack.await.expect("the refusal is written");
            tokio::time::Instant::now()
        };
        let (_stop, written_at) = tokio::join!(
            relay_backend_messages(upstream, &mut acc.relay, &mut acc.taken),
            written,
        );

        assert_eq!(
            written_at - started,
            REFUSAL_ORDER_STALL_TIMEOUT,
            "the wait is bounded by the stall window, not unbounded"
        );
        assert_eq!(
            acc.relay.abandoned_flushes, 1,
            "the flush that was never answered is given up on"
        );
        assert!(
            acc.releasable_now(),
            "one stall window for the whole session, not one per refusal"
        );
    }

    #[tokio::test]
    async fn an_answer_written_off_and_then_delivered_late_is_not_counted_twice() {
        // Giving up on an answer must not be recorded as the client having
        // received it. If it were, a late arrival would take the credit a second
        // time and release the *next* refusal before its own answer — losing the
        // ordering the write-off was only meant to make affordable. Keeping what
        // was delivered and what was given up on apart is what makes that
        // impossible rather than merely guarded.
        let mut acc = accounting().await;
        acc.link.forwarded_sync_point();
        acc.abandon();
        assert_eq!(
            acc.link.forwarded.sync_points.load(Ordering::Relaxed),
            1,
            "a write-off never lowers what was forwarded"
        );
        assert_eq!(
            (acc.relay.answered, acc.relay.abandoned),
            (0, 1),
            "the answer that never came is recorded beside what was delivered, not inside it"
        );
        assert!(
            acc.releasable_now(),
            "the refusal that paid the window is not made to pay it again"
        );

        // The database was slow, not silent: the answer arrives after all.
        acc.relay.delivered(b'Z');
        assert_eq!(
            (acc.relay.answered, acc.relay.abandoned),
            (1, 1),
            "a late answer is counted once, where it belongs"
        );

        // So the next statement's refusal still waits for its own answer.
        acc.link.forwarded_sync_point();
        assert!(
            !acc.releasable_now(),
            "the refusal after a write-off is still ordered behind its own answer"
        );
    }

    #[tokio::test]
    async fn a_late_written_off_answer_does_not_release_a_refusal_behind_a_later_query() {
        // The dangerous shape is a write-off, *then* another query, *then* the
        // written-off answer. The later query raised what the next refusal is
        // measured against, so a stale answer credited into that slot would
        // release the refusal queued behind the later query before the database
        // has answered it. That is #101, reached the long way round.
        let mut acc = accounting().await;

        // Query A goes out and is never answered.
        acc.link.forwarded_sync_point();
        acc.abandon();

        // Query B goes out while A is still owed.
        acc.link.forwarded_sync_point();
        // A's answer finally arrives — B's has not.
        acc.relay.delivered(b'Z');

        assert!(
            !acc.releasable_now(),
            "a written-off statement's late answer does not answer for the statement after it"
        );
    }

    #[tokio::test]
    async fn a_query_forwarded_after_a_write_off_is_still_released_by_its_own_answer() {
        // The other half of the same rule, and the easy thing to break while
        // fixing the first: a late answer must still be counted, or the barrier
        // stays permanently one short and every refusal for the rest of the
        // session pays the stall bound again — which is what the write-off exists
        // to prevent.
        let mut acc = accounting().await;

        acc.link.forwarded_sync_point();
        acc.abandon();
        acc.link.forwarded_sync_point();
        // A's late answer, then B's own.
        acc.relay.delivered(b'Z');
        acc.relay.delivered(b'Z');

        assert!(
            acc.releasable_now(),
            "the statement after a write-off is released by its own answer, at once"
        );
    }

    #[tokio::test]
    async fn a_write_off_settles_both_counters_without_crossing_their_accounting() {
        // The two sides are given up on together and recorded separately. A
        // write-off that let a later real `ReadyForQuery` be absorbed by the flush
        // side, or a quiet absorbed by the sync side, would leave the next
        // refusal on the connection paying the stall bound all over again.
        let mut acc = accounting().await;
        acc.link.forwarded_sync_point();
        acc.link.forwarded_flush();

        acc.abandon();
        assert_eq!(
            (acc.relay.abandoned, acc.relay.abandoned_flushes),
            (1, 1),
            "both sides are given up on, each in its own counter"
        );

        // The statement's answer turns up late. It counts for the statement and
        // says nothing about the flush, which was sent after its `Sync`.
        acc.relay.delivered(b'Z');
        assert_eq!(
            (acc.relay.answered, acc.relay.drained),
            (1, 0),
            "the late answer was credited to the statement, not to the flush"
        );

        // So the next statement is still ordered behind its own answer, and the
        // next flush behind its own output.
        acc.link.forwarded_sync_point();
        acc.link.forwarded_flush();
        assert!(
            !acc.releasable_now(),
            "the write-off left a later refusal released early"
        );
    }

    #[tokio::test]
    async fn a_written_off_flush_is_not_settled_again_by_the_next_batch() {
        // A written-off flush is not gone: the batch the database gave up
        // answering can still produce its output afterwards. If the quiet behind
        // that late output were credited to the flush still outstanding, the next
        // refusal would be released while the second batch was still computing —
        // #101, reached through the write-off.
        let mut acc = accounting().await;
        acc.link.forwarded_flush();

        acc.abandon();
        assert_eq!(
            (acc.relay.drained, acc.relay.abandoned_flushes),
            (0, 1),
            "the flush given up on is recorded as such, and nothing is credited as delivered"
        );

        // The client's next batch, allowed and flushed like the first.
        acc.link.forwarded_flush();

        // Now the *first* batch's output finally arrives, and the relay finds the
        // socket quiet behind it.
        acc.quiet();
        assert_eq!(
            acc.relay.drained, 1,
            "the late drain counted one flush, which is all one quiet can prove"
        );
        assert!(
            !acc.releasable_now(),
            "the write-off let a refusal overtake the batch that followed it"
        );
    }

    #[tokio::test]
    async fn a_sync_point_that_covers_a_written_off_flush_settles_it() {
        // A `ReadyForQuery` proves the output of every flush before its `Sync`
        // was emitted, written-off ones included. Recording that is what keeps the
        // *next* batch from paying a stall window for output the client already
        // has: the quiet after it belongs to that batch and has to count for it.
        let mut acc = accounting().await;
        acc.link.forwarded_flush();
        acc.abandon();

        // The client's next batch, flushed and then synced, and the database
        // answers the whole thing as one burst — so the relay never sees a quiet,
        // and the `Z` is what settles it.
        acc.link.forwarded_flush();
        acc.link.forwarded_sync_point();
        acc.relay.delivered(b'Z');
        assert_eq!(
            acc.relay.drained, 2,
            "the answer proved the output of every flush before its Sync"
        );

        // A third batch, settled the ordinary way. Its quiet must count for the
        // batch it belongs to rather than for one already accounted for.
        acc.link.forwarded_flush();
        acc.quiet();
        assert_eq!(
            acc.relay.drained, 3,
            "the quiet settled a flush already proved instead of its own batch"
        );
        assert!(
            acc.releasable_now(),
            "the batch was answered, so the refusal is released without a stall"
        );
    }

    #[tokio::test]
    async fn a_partly_covering_answer_accounts_only_for_the_flushes_it_proves() {
        // Two write-offs can stack before the first sync point's answer lands,
        // and that answer then covers only the earlier flush. Crediting it for
        // both would release a refusal ahead of the second batch's output.
        let mut acc = accounting().await;
        acc.link.forwarded_flush();
        acc.link.forwarded_sync_point();
        acc.abandon();

        // A second flushed batch, written off in its own stall window while the
        // first sync point is still unanswered.
        acc.link.forwarded_flush();
        acc.abandon();
        assert_eq!(
            (acc.relay.abandoned, acc.relay.abandoned_flushes),
            (1, 2),
            "both flushes were given up on, and the one sync point once"
        );

        // The first sync point's answer finally arrives. It proves the output of
        // the flush it covers — the first — and nothing about the second.
        acc.relay.delivered(b'Z');
        assert_eq!(
            acc.relay.drained, 1,
            "the answer proved one flush, so exactly one is accounted for"
        );

        // One quiet settles what is genuinely still owed, and the next settles the
        // batch it belongs to.
        acc.link.forwarded_flush();
        acc.quiet();
        acc.quiet();
        assert_eq!(
            acc.relay.drained, 3,
            "a flush already proved swallowed the quiet that should have settled this batch"
        );
        assert!(acc.releasable_now());
    }

    #[tokio::test]
    async fn the_relay_hands_its_writer_back_only_while_the_client_stream_is_framed() {
        // The writer *is* the permission. A relay that stopped between messages
        // gives it back, so a refusal decided after it stopped is still answered;
        // one that stopped inside a message does not, so nothing can be appended
        // to the partial frame the client is left holding. Neither is a flag
        // anything checks.
        let (_between_peer, honmoon_end) = socket_pair().await;
        let (_read, client_write) = honmoon_end.into_split();
        let (_injections, taken) = mpsc::channel(1);
        let clean = ScriptedUpstream::new([(std::time::Duration::ZERO, Vec::new())]);
        assert!(
            upstream_to_client(clean, client_write, taken, Arc::new(Forwarded::new()))
                .await
                .is_some(),
            "an upstream that ends between messages leaves the client's stream framed"
        );

        // A message too large to buffer is written head-first and streamed, so an
        // upstream that dies part-way through its payload leaves the client
        // holding a header whose payload never arrived.
        let (_mid_peer, honmoon_end) = socket_pair().await;
        let (_read, client_write) = honmoon_end.into_split();
        let (_injections, taken) = mpsc::channel(1);
        let truncated = ScriptedUpstream::new([
            (std::time::Duration::ZERO, oversized_head()),
            (std::time::Duration::ZERO, Vec::new()),
        ]);
        assert!(
            upstream_to_client(truncated, client_write, taken, Arc::new(Forwarded::new()))
                .await
                .is_none(),
            "an upstream that dies inside a message leaves nothing that could write to the client"
        );
    }

    /// The head of a `CopyData` message too large for the relay to buffer, so it
    /// is written to the client before its payload is streamed.
    fn oversized_head() -> Vec<u8> {
        let payload_len = (MAX_BUFFERED_BACKEND_MESSAGE + 1_000) as u32;
        let mut head = vec![b'd'];
        head.extend_from_slice(&(payload_len + 4).to_be_bytes());
        head
    }

    #[tokio::test]
    async fn a_relay_that_dies_mid_message_suppresses_the_refusal_rather_than_corrupting_it() {
        // The client holds a frame header whose payload never arrived, so its
        // stream is already desynchronised: it would read an injected
        // `ErrorResponse` as that payload's remainder. A truncated connection is
        // the honest outcome; adding bytes to it makes the truncation unreadable.
        //
        // The refusal is queued *before* the stream breaks and is still waiting on
        // an earlier statement's answer when it does, which is the case the old
        // writer lock needed a second check for: there is now no writer to reach
        // it with, so there is nothing to check.
        let (mut peer, honmoon_end) = socket_pair().await;
        let (_read, client_write) = honmoon_end.into_split();
        let forwarded = Arc::new(Forwarded::new());
        let (injections, taken) = mpsc::channel(1);
        let link = ClientLink {
            forwarded: Arc::clone(&forwarded),
            injections,
        };
        // One statement is still owed its answer, so the refusal cannot go out
        // before the relay reaches the frame that breaks the stream.
        link.forwarded_sync_point();
        let mut ack = queue_refusal(&link, "honmoon: denied by policy");

        let truncated = ScriptedUpstream::new([
            (std::time::Duration::ZERO, oversized_head()),
            (std::time::Duration::ZERO, Vec::new()),
        ]);
        assert!(
            upstream_to_client(truncated, client_write, taken, forwarded)
                .await
                .is_none()
        );
        assert!(
            ack.try_recv().is_err(),
            "the refusal must not have been written onto a partial frame"
        );

        drop(link);
        let mut seen = Vec::new();
        peer.read_to_end(&mut seen).await.unwrap();
        assert_eq!(
            seen,
            oversized_head(),
            "nothing may follow a partial frame, got {seen:?}"
        );
    }

    /// An upstream that records what honmoon had already counted at the moment
    /// the packet reached it. This is the interleaving a fast database on a
    /// multi-threaded runtime produces: the answer can be on the client's socket
    /// before the forwarding task runs its next line.
    struct CountsWhenWritten {
        forwarded: Arc<Forwarded>,
        counted: Option<u64>,
    }

    impl AsyncWrite for CountsWhenWritten {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if self.counted.is_none() {
                self.counted = Some(self.forwarded.sync_points.load(Ordering::Relaxed));
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

    #[tokio::test]
    async fn an_answer_that_beats_the_forward_being_recorded_is_not_discarded() {
        // Sync points are counted before the bytes go out precisely so this
        // ordering is impossible. Counting afterwards lets the clamp in
        // `Relay::delivered` read a `forwarded` that is still zero and throw the
        // answer away, and the counts stay one apart for the rest of the session —
        // every later refusal then waits out the whole stall window for a
        // response the client is already holding.
        let mut acc = accounting().await;
        let mut client = std::io::Cursor::new(startup_packet(PROTOCOL_V3, b"user\0pg\0\0"));
        let mut upstream = CountsWhenWritten {
            forwarded: Arc::clone(&acc.link.forwarded),
            counted: None,
        };

        assert!(
            startup(&mut client, &mut upstream, &acc.link)
                .await
                .unwrap()
        );
        assert_eq!(
            upstream.counted,
            Some(1),
            "the handshake's sync point was counted before its packet went out"
        );

        // So an answer relayed at that instant is credited rather than clamped
        // away as an over-count.
        acc.relay.delivered(b'Z');
        assert_eq!(acc.relay.answered, 1, "the answer was not discarded");
        assert!(
            acc.releasable_now(),
            "the handshake was answered, so nothing is owed and the refusal waits for nothing"
        );

        // And the clamp still does the job it is there for: a backend that sends
        // more `ReadyForQuery` frames than it was asked for cannot buy a refusal
        // its way past a statement nobody has answered.
        acc.relay.delivered(b'Z');
        assert_eq!(
            acc.relay.answered, 1,
            "a `ReadyForQuery` for a sync point that was never forwarded was counted"
        );
    }

    #[tokio::test]
    async fn a_relay_that_stops_releases_the_refusal_waiting_behind_it() {
        let state = GatewayState::new(deny_drop_policy());
        // The database goes away while the refusal is queued behind its answer.
        // Nothing is left to order against, so it must go out at once: a refusal
        // still queued when the relay drops its writer is lost, and a client
        // whose own socket is fine reads an unexplained close instead of its
        // 42501 (ADR-0007).
        let mut client = std::io::Cursor::new(pipelined_select_then_drop());
        let mut upstream: Vec<u8> = Vec::new();
        let Session {
            link,
            client: mut peer,
            database,
            _relay,
        } = session().await;

        let facts = Facts::default();
        let run = message_loop(&state, &mut client, &mut upstream, &link, &facts);
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

        let (ended, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(run, client_view)
        })
        .await
        .expect("the refusal is written as soon as the relay ends, not after the stall bound");
        assert!(ended.unwrap().drain);
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
        let Session {
            link,
            client: mut peer,
            mut database,
            _relay,
        } = session().await;

        let facts = Facts::default();
        let run = message_loop(&state, &mut client, &mut upstream, &link, &facts);
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

        let (ended, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(run, client_view)
        })
        .await
        .expect("the session finished");
        assert!(ended.unwrap().drain);
    }

    #[tokio::test]
    async fn a_refusal_waits_for_a_batch_the_client_only_flushed() {
        let state = GatewayState::new(deny_drop_policy());
        // The pipeline-mode path: `Parse`/`Bind`/`Execute`/`Flush` and no
        // `Sync`, so the batch earns no `ReadyForQuery` and #112's sync-point
        // barrier counts nothing for it. The refusal for the statement behind it
        // would then be injected while the batch's rows are still in flight, and
        // the client would read honmoon's 42501 against the slot of a statement
        // the database allowed (#113).
        let mut frames = parse_frame("stmt", "SELECT 1");
        frames.extend_from_slice(&flush_driven_batch("stmt"));
        frames.extend_from_slice(&parse_frame("doomed", "DROP TABLE users"));
        let mut client = std::io::Cursor::new(frames);
        let mut upstream: Vec<u8> = Vec::new();
        let Session {
            link,
            client: mut peer,
            mut database,
            _relay,
        } = session().await;

        let facts = Facts::default();
        let run = message_loop(&state, &mut client, &mut upstream, &link, &facts);
        let client_view = async {
            let mut early = [0u8; 1];
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    peer.read_exact(&mut early),
                )
                .await
                .is_err(),
                "the refusal overtook the flushed batch it was pipelined behind"
            );

            database.write_all(&flushed_batch_response()).await.unwrap();

            let seen = [
                read_message_tag(&mut peer).await,
                read_message_tag(&mut peer).await,
                read_message_tag(&mut peer).await,
                read_message_tag(&mut peer).await,
                read_message_tag(&mut peer).await,
            ];
            assert_eq!(
                seen,
                [b'1', b'2', b'C', b'E', b'Z'],
                "the whole flushed batch reaches the client before the refusal"
            );
        };

        let (ended, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(run, client_view)
        })
        .await
        .expect("the session finished");
        assert!(ended.unwrap().drain);
        assert!(
            !upstream
                .windows(b"DROP TABLE users".len())
                .any(|w| w == b"DROP TABLE users"),
            "the denied statement never reached the database"
        );
    }

    /// Assert honmoon's queued answer has not reached the client yet.
    async fn still_waiting(ack: &mut oneshot::Receiver<()>, why: &str) {
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), &mut *ack)
                .await
                .is_err(),
            "{why}"
        );
    }

    /// Assert honmoon's queued answer reaches the client.
    async fn written(ack: &mut oneshot::Receiver<()>, why: &str) {
        match tokio::time::timeout(std::time::Duration::from_secs(10), &mut *ack).await {
            Ok(Ok(())) => {}
            _ => panic!("{why}"),
        }
    }

    #[tokio::test]
    async fn a_quiet_upstream_does_not_settle_a_flush_the_database_has_not_reached_yet() {
        // The flush barrier is settled by the upstream falling silent, so it has
        // to be silence *after* the batch's own output. A batch pipelined behind
        // a simple query is answered second: the quiet that follows the query's
        // `ReadyForQuery` says nothing about the batch, and settling the flush
        // there would release the refusal before the batch reached the client —
        // #113 again, one message later.
        let Session {
            link,
            client: mut peer,
            mut database,
            _relay,
        } = session().await;
        link.forwarded_sync_point();
        link.forwarded_flush();
        let mut ack = queue_refusal(&link, "honmoon: denied by policy");

        // The simple query is answered, and the upstream then goes quiet.
        database.write_all(&query_response()).await.unwrap();
        assert_eq!(read_message_tag(&mut peer).await, b'C');
        assert_eq!(read_message_tag(&mut peer).await, b'Z');
        still_waiting(
            &mut ack,
            "the query's own answer settled the flush queued behind it",
        )
        .await;

        // Only the batch's own output settles it.
        database.write_all(&flushed_batch_response()).await.unwrap();
        written(
            &mut ack,
            "the batch was delivered, so the refusal is released",
        )
        .await;
    }

    #[tokio::test]
    async fn a_database_quiet_between_rows_has_not_finished_the_batch_it_flushed() {
        // The flush barrier reads a quiet upstream as "the flushed output is all
        // delivered", so it must not read one part-way through a result set. No
        // `Execute` ends on a `DataRow` — `CommandComplete` does — so a backend
        // that has emitted rows and paused is still working, and settling there
        // would drop the refusal into the middle of the rows: worse than the
        // misattribution #101 removed, and the case #112 added the
        // stall-window-per-message rule for.
        let Session {
            link,
            client: mut peer,
            mut database,
            _relay,
        } = session().await;
        link.forwarded_flush();
        let mut ack = queue_refusal(&link, "honmoon: denied by policy");

        let mut partial = vec![b'1', 0, 0, 0, 4, b'2', 0, 0, 0, 4];
        partial.extend_from_slice(&[b'D', 0, 0, 0, 11, 0, 1, 0, 0, 0, 1, b'x']);
        database.write_all(&partial).await.unwrap();
        for expected in *b"12D" {
            assert_eq!(read_message_tag(&mut peer).await, expected);
        }
        still_waiting(
            &mut ack,
            "a pause between rows settled a batch the database is still streaming",
        )
        .await;

        // `CommandComplete` really does end it, and then the refusal is released.
        database.write_all(&command_complete()).await.unwrap();
        written(&mut ack, "the batch ended, so the refusal is released").await;
    }

    #[tokio::test]
    async fn a_notice_raised_mid_statement_does_not_settle_the_flush_it_arrived_under() {
        // `NoticeResponse` is asynchronous: a function that `RAISE NOTICE`s and
        // then keeps working flushes the notice and goes quiet with its
        // `CommandComplete` still to come. Reading that quiet as a finished
        // batch releases the refusal ahead of the allowed statement's own
        // response, which is #101 — the same shape as the `DataRow` pause, and
        // why the guard lists what can never end a batch rather than trusting
        // anything that is not a row.
        let Session {
            link,
            client: mut peer,
            mut database,
            _relay,
        } = session().await;
        link.forwarded_flush();
        let mut ack = queue_refusal(&link, "honmoon: denied by policy");

        let notice = b"SNOTICE\0Mstill working\0\0";
        let mut partial = vec![b'1', 0, 0, 0, 4, b'2', 0, 0, 0, 4, b'N'];
        partial.extend_from_slice(&((4 + notice.len()) as u32).to_be_bytes());
        partial.extend_from_slice(notice);
        database.write_all(&partial).await.unwrap();
        for expected in *b"12N" {
            assert_eq!(read_message_tag(&mut peer).await, expected);
        }
        still_waiting(
            &mut ack,
            "a notice raised mid-statement settled a batch the database is still computing",
        )
        .await;

        // The statement's own completion really does end it.
        database.write_all(&command_complete()).await.unwrap();
        written(&mut ack, "the batch ended, so the refusal is released").await;
    }

    #[tokio::test]
    async fn a_row_description_before_the_rows_does_not_settle_the_flush() {
        // `RowDescription` answers a `Describe`, and a `Bind`/`Describe`/
        // `Execute`/`Flush` batch emits it before the first row. A backend that
        // has planned the query and not yet produced a row pauses exactly
        // there, so settling on it drops the refusal in front of the whole
        // result set. `ParameterDescription` was already excluded for the same
        // reason; leaving `RowDescription` in was an inconsistency in that list.
        let Session {
            link,
            client: mut peer,
            mut database,
            _relay,
        } = session().await;
        link.forwarded_flush();
        let mut ack = queue_refusal(&link, "honmoon: denied by policy");

        // `BindComplete`, then a one-column `RowDescription`.
        let mut partial = vec![b'2', 0, 0, 0, 4];
        partial.extend_from_slice(&[b'T', 0, 0, 0, 26, 0, 1]);
        partial.extend_from_slice(b"x\0");
        partial.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 0, 4]);
        partial.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0, 0]);
        database.write_all(&partial).await.unwrap();
        for expected in *b"2T" {
            assert_eq!(read_message_tag(&mut peer).await, expected);
        }
        still_waiting(
            &mut ack,
            "a pause before the first row settled a batch whose result set has not started",
        )
        .await;

        // The rows, and then the completion that really ends it.
        database
            .write_all(&[b'D', 0, 0, 0, 11, 0, 1, 0, 0, 0, 1, b'x'])
            .await
            .unwrap();
        database.write_all(&command_complete()).await.unwrap();
        written(&mut ack, "the batch ended, so the refusal is released").await;
    }

    #[tokio::test]
    async fn one_quiet_upstream_settles_one_flush_and_not_the_ones_behind_it() {
        // A client may flush mid-batch — `Parse`/`Bind`/`Flush`/`Execute`/
        // `Flush`, which is what `PQsendFlushRequest` is for. The backend
        // answers the first flush with `ParseComplete`/`BindComplete` and then
        // goes quiet while it computes the `Execute`. That quiet settles the
        // first flush and must settle no more: crediting every outstanding
        // flush from one observation releases the refusal ahead of the rows,
        // which is #101 reached through the fix for #113.
        let Session {
            link,
            client: mut peer,
            mut database,
            _relay,
        } = session().await;
        link.forwarded_flush();
        link.forwarded_flush();
        let mut ack = queue_refusal(&link, "honmoon: denied by policy");

        database
            .write_all(&[b'1', 0, 0, 0, 4, b'2', 0, 0, 0, 4])
            .await
            .unwrap();
        for expected in *b"12" {
            assert_eq!(read_message_tag(&mut peer).await, expected);
        }
        still_waiting(&mut ack, "one quiet upstream settled both flushes").await;

        // The `Execute`'s own output settles the second — so exactly one flush
        // was settled by the one quiet before it, and the second by its own.
        database.write_all(&command_complete()).await.unwrap();
        written(
            &mut ack,
            "both flushes are settled once both batches have been delivered",
        )
        .await;
    }

    #[tokio::test]
    async fn a_database_quiet_between_copy_rows_has_not_finished_the_batch_it_flushed() {
        // The `CopyData` half of the same rule. A pause between copy rows is a
        // backend still streaming — and `CopyData` frames are the ones the
        // relay's own comments call arbitrarily large, so pausing between them
        // is the expected shape rather than an unlikely one.
        //
        // `CopyDone` does not end it either: the backend still owes the COPY's
        // `CommandComplete`, so a quiet after `CopyDone` is one more message
        // short of the batch being answered.
        let Session {
            link,
            client: mut peer,
            mut database,
            _relay,
        } = session().await;
        link.forwarded_flush();
        let mut ack = queue_refusal(&link, "honmoon: denied by policy");

        // `CopyOutResponse` (textual, no columns), then one `CopyData` row.
        let mut partial = vec![b'H', 0, 0, 0, 7, 0, 0, 0];
        partial.extend_from_slice(&[b'd', 0, 0, 0, 6, b'x', b'\n']);
        database.write_all(&partial).await.unwrap();
        for expected in *b"Hd" {
            assert_eq!(read_message_tag(&mut peer).await, expected);
        }
        still_waiting(
            &mut ack,
            "a pause between copy rows settled a copy the database is still streaming",
        )
        .await;

        // `CopyDone` closes the data stream but not the statement.
        database.write_all(&[b'c', 0, 0, 0, 4]).await.unwrap();
        assert_eq!(read_message_tag(&mut peer).await, b'c');
        still_waiting(
            &mut ack,
            "a quiet after `CopyDone` settled a copy whose `CommandComplete` is still owed",
        )
        .await;

        // The COPY's own `CommandComplete` really does end it.
        let tag = b"COPY 1\0";
        let mut done = vec![b'C'];
        done.extend_from_slice(&((4 + tag.len()) as u32).to_be_bytes());
        done.extend_from_slice(tag);
        database.write_all(&done).await.unwrap();
        written(&mut ack, "the copy ended, so the refusal is released").await;
    }

    #[tokio::test]
    async fn a_batch_ending_flush_then_sync_is_settled_by_its_ready_for_query() {
        // What a libpq pipeline does at `PQpipelineSync()`: flush the batch,
        // then sync. The completions and the `ReadyForQuery` come back as one
        // burst, so the relay never sees a quiet before the `Z` — and a `Z` is
        // a stronger settlement than that quiet anyway, because PostgreSQL
        // answers in order. Without crediting it there, the commonest pipeline
        // shape of all pays the whole stall window on its first refusal.
        let state = GatewayState::new(deny_drop_policy());
        let mut frames = parse_frame("stmt", "SELECT 1");
        frames.extend_from_slice(&flush_driven_batch("stmt"));
        frames.extend_from_slice(&[b'S', 0, 0, 0, 4]);
        frames.extend_from_slice(&parse_frame("doomed", "DROP TABLE users"));
        let mut client = std::io::Cursor::new(frames);
        let mut upstream: Vec<u8> = Vec::new();
        let Session {
            link,
            client: mut peer,
            mut database,
            _relay,
        } = session().await;

        let facts = Facts::default();
        let run = message_loop(&state, &mut client, &mut upstream, &link, &facts);
        let client_view = async {
            // The whole answer in one write, exactly as the burst arrives.
            let mut answer = flushed_batch_response();
            answer.extend_from_slice(&[b'Z', 0, 0, 0, 5, b'I']);
            database.write_all(&answer).await.unwrap();

            let seen = [
                read_message_tag(&mut peer).await,
                read_message_tag(&mut peer).await,
                read_message_tag(&mut peer).await,
                read_message_tag(&mut peer).await,
                read_message_tag(&mut peer).await,
                read_message_tag(&mut peer).await,
            ];
            assert_eq!(
                seen,
                [b'1', b'2', b'C', b'Z', b'E', b'Z'],
                "the batch and its sync point reach the client before the refusal"
            );
        };

        // A real clock deliberately: the stall window is 30s, so finishing well
        // inside it is the assertion. A paused clock cannot make it — it jumps
        // to the next timer deadline while the socket read resolves, the caveat
        // `a_pipeline_that_keeps_moving_never_hits_the_stall_bound` records for
        // exactly this shape of test.
        let (ended, ()) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(run, client_view)
        })
        .await
        .expect("the sync point settled the flush before it, so nothing stalled");
        assert!(ended.unwrap().drain);
    }

    #[tokio::test]
    async fn a_ready_for_query_does_not_settle_a_flush_sent_after_its_sync() {
        // The trap in crediting a `Z` for outstanding flushes: it speaks only
        // for what preceded its own `Sync`. A `Flush` sent afterwards is not
        // answered by it, and crediting it there would release a refusal ahead
        // of that batch's output — so the credit is bounded by the snapshot
        // taken when the sync point was forwarded, not by the live count.
        let Session {
            link,
            client: mut peer,
            mut database,
            _relay,
        } = session().await;

        // `Flush` A, then `Sync`, then `Flush` B — and no second sync point.
        link.forwarded_flush();
        link.forwarded_sync_point();
        link.forwarded_flush();
        let mut ack = queue_refusal(&link, "honmoon: denied by policy");

        // Batch A's output and the sync point's answer, in one burst.
        let mut answer = flushed_batch_response();
        answer.extend_from_slice(&[b'Z', 0, 0, 0, 5, b'I']);
        database.write_all(&answer).await.unwrap();
        for expected in *b"12CZ" {
            assert_eq!(read_message_tag(&mut peer).await, expected);
        }
        still_waiting(
            &mut ack,
            "the ReadyForQuery settled a flush sent after its own Sync",
        )
        .await;

        // Batch B's own output settles the second.
        database.write_all(&flushed_batch_response()).await.unwrap();
        written(
            &mut ack,
            "batch B was delivered, so the refusal is released",
        )
        .await;
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
        let Session {
            link,
            client: mut peer,
            mut database,
            _relay,
        } = session().await;

        let facts = Facts::default();
        let run = client_to_upstream(&state, &mut client, &mut upstream, &link, &facts);
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

        let (ended, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(run, client_view)
        })
        .await
        .expect("the session finished");
        assert!(ended.unwrap().drain);
        assert!(
            !upstream
                .windows(b"DROP TABLE users".len())
                .any(|w| w == b"DROP TABLE users"),
            "the denied statement never reached the database"
        );
    }
}
