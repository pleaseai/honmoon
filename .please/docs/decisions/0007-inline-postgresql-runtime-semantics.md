# ADR-0007: Inline PostgreSQL runtime semantics

## Status

Accepted

## Context

Phase 3 gave honmoon a PostgreSQL wire parser (`parse_postgres_query`) and a SQL verb/table
heuristic (`parse_sql`), both engine-complete and tested against synthetic packets. What it never
had was a socket: nothing fed those parsers from real traffic, so a `DROP TABLE` rule was provable
in a unit test and inert in production. That gap is TD-006.

[ADR-0005](0005-empty-namespace-and-bridged-proxy-sockets.md) settled the **transport**. A SOCKS5
listener sits beside the CONNECT proxy; its handshake states the destination `host:port` in the
clear, which is what `Policy::endpoint_for` needs to pick an endpoint, and §4 fixed the shape of
what comes next: a protocol runtime receives a connection whose endpoint is already known, parses
frames into `Facts`, calls the engine, and forwards, closes, or holds.

What ADR-0005 deliberately left open is everything about the PostgreSQL runtime itself, and every
open question has a fail-open answer that looks reasonable in isolation:

- The protocol opens with an **encryption negotiation**. A runtime that just proxies it inspects
  nothing afterwards.
- The protocol has **two ways to submit a statement** — the simple `Q` and the extended-protocol
  `Parse`/`Bind`/`Execute`. Covering only `Q` means any driver using prepared statements (most of
  them) is uninspected.
- A refused statement has **no obvious response**. Closing the socket is the easy implementation
  and the worst diagnostic.
- Inspecting a frame means **buffering it**, which needs a cap, and the existing HTTP body cap
  (2 MiB) forwards what it cannot inspect.

## Decision

**Refuse encryption between the client and honmoon.** `SSLRequest` (80877103) and `GSSENCRequest`
(80877104) are answered with the single byte `N` and never forwarded; the client then sends a
plain `StartupMessage` and the session proceeds in cleartext to honmoon. Inline inspection needs
plaintext, and terminating TLS here would mean minting a server certificate the database's own
clients would have to trust — a second CA story for one protocol. The **upstream leg is plaintext
in v0.1.0**; TLS from honmoon to the database is a follow-up, and until it lands the runtime is
for a database honmoon can reach over a trusted network path (a sidecar, a bastion, loopback).
Only `StartupMessage` (196608) and `CancelRequest` (80877102) are forwarded verbatim; any other
startup code closes the connection.

**Inspect both statement-bearing messages.** `Q` is parsed by `parse_postgres_query` over the
whole frame; `P` (Parse) has its query extracted from `statement_name\0 query\0 …` and run through
`parse_sql`. Both produce `Facts { endpoint, domain, sql }` for `decide_explained`, so one rule
(`sql.verb == 'DROP'`) covers a `psql` one-liner and a driver's prepared statement alike. Every
other frontend message — `Bind`, `Execute`, `Sync`, `CopyData`, `Close`, `Terminate` — is streamed
through without buffering, and upstream→client is a raw copy.

**A refused statement gets an `ErrorResponse`, not a closed socket.** Honmoon writes `E` with
severity `ERROR`, SQLSTATE **`42501`** (insufficient privilege) and a message naming the rule
(`honmoon: denied by policy rule no-destructive-sql`), followed by `ReadyForQuery` with status
`I`. Every driver already renders 42501 as a permission error, so the refusal arrives as an
actionable message in the application's own error handling instead of a connection reset the
developer has to bisect. The session stays open, so the next statement works — the connection is
not collateral damage of one refused query.

**The 1 MiB frame cap fails closed.** A `Q`/`P` frame whose declared length exceeds
`MAX_PG_FRAME` is not inspected and therefore not forwarded: honmoon discards exactly the declared
bytes (so the stream stays framed) and answers the same `ErrorResponse`/`ReadyForQuery` pair with
`honmoon: query frame exceeds inspection cap`. **This is the opposite of the HTTP 2 MiB body cap**,
which forwards an over-cap body un-inspected and logs a warning. The divergence is deliberate: an
HTTP body over the cap is a large upload whose *destination host* was already authorized, while a
SQL statement over the cap is the statement itself — `DROP TABLE users; -- <1 MiB of spaces>` would
otherwise be a one-line bypass of every SQL rule. The same reasoning applies to a `Q`/`P` frame
that fails to parse: it is refused rather than forwarded blind.

## Consequences

- **`psql "sslmode=require"` fails to connect** through the runtime, as do drivers configured to
  demand TLS. `sslmode=prefer` (the libpq default) and `sslmode=disable` work: prefer sees the `N`
  and falls back to plaintext. Operators who need TLS on the client leg must wait for the upstream
  TLS follow-up, which will bring a server-certificate story with it.
- **Only `Parse` is inspected in the extended protocol.** `Bind` parameter values, `Execute`,
  function-call messages (`F`), and `COPY` data (`d`) are forwarded verbatim. So a statement is
  gated when it is *prepared*, not when it is executed: an `EXECUTE` of a statement prepared before
  the rule existed, or a `DELETE FROM t WHERE id = $1` whose destructiveness lives entirely in the
  bound parameter, is not re-decided. Facts are drawn from the SQL text, which is where the verb
  and table live.
- **Denying a `P` leaves the client's pipeline out of sync until `Sync`.** The client sent
  `Parse`/`Bind`/`Execute`/`Sync` as a batch; honmoon dropped the `Parse` and answered the error
  itself, so the `Bind` that follows errors upstream against an unknown statement. The client sees
  honmoon's 42501 first and one further error, then `ReadyForQuery` restores the session. This is
  accepted rather than papered over: buffering the whole pipeline to rewrite it would mean
  honmoon reordering a protocol it does not otherwise interpret.
- **The runtime only engages for a declared endpoint.** A connection to a `(host, port)` with no
  matching `endpoints` entry — or one declared `protocol: tcp` — is a raw SOCKS5 tunnel gated once
  on `Facts { domain }`, with no SQL inspection at all. Declaring the endpoint is what turns SQL
  rules on, and a rule naming an endpoint the policy never declares is inert (the engine already
  warns about that at load).
- **A `postgres` endpoint is gated twice: once at connect, then per statement.** The SOCKS5
  handshake is gated exactly like a CONNECT (`Facts { domain, endpoint }` → `decide_explained`),
  so `egress.default: deny` refuses the connection before the runtime ever sees it — declaring an
  endpoint is not a way past the default. Only an admitted connection reaches the runtime, which
  then decides each statement. Without this the two data paths would disagree about what the
  egress default means: it would block a `kubernetes` endpoint over HTTPS while silently admitting
  a `postgres` one, and a firewall must not have a protocol that ignores its own default.
- **Statement rules do not fire at connect time, but rule *order* still matters.** A condition
  over `sql.*` cannot match facts that carry no statement yet, and the engine treats an unknown
  fact reference as no match (fail-closed), so under `egress.default: allow` the connection gate
  changes nothing. Under `egress.default: deny` the endpoint needs an explicit connection-level
  `allow` rule (`condition: "true"`), and because the first matching rule wins that rule must be
  ordered **after** the statement denies — an `allow` placed first would answer every query.
- **`honmoon run` reaches this runtime through `ALL_PROXY`, not `http_proxy`.** The wrapper binds
  the SOCKS5 listener beside its CONNECT proxy and hands the child
  `ALL_PROXY=socks5h://127.0.0.1:<port>`; the `h` keeps DNS on honmoon's side, which is what puts
  the hostname into the handshake where the `endpoints` lookup above happens. A client that reads
  neither proxy variable — `psql` among them — reaches nothing under `run` at all, which is
  ADR-0005's fail-closed default rather than a gap in this one.
- **The upstream→client relay owns the client write half, and every answer honmoon writes itself
  goes through it.** Honmoon's `ErrorResponse`/`ReadyForQuery` lands in a stream that relay is
  writing at the same time, so the runtime does not write it from the task that read the statement:
  the message loop hands the answer to the relay over a one-slot channel and the relay writes it
  between two complete backend messages. That is where the framing guarantee comes from — one
  writer, whole messages — and it is ownership rather than a lock, so there is no order in which two
  tasks can take one wrongly. The single byte `N` that refuses encryption goes the same way, so the
  claim holds from the first byte of the session rather than from the first statement.
- **A local answer is injected in request order, not just on a frame boundary.** Framing alone is
  not enough. A client that pipelines `SELECT pg_sleep(1); DROP TABLE users;` would read the refusal
  for the `DROP` before the `SELECT`'s response and attribute the 42501 to the statement that in
  fact succeeded — a firewall telling the truth about the wrong query. So the runtime counts **sync
  points**: the completed startup handshake, then every `Q`, `Sync` and `FunctionCall` it forwards,
  each of which the database answers with exactly one `ReadyForQuery`. The answer is tagged with
  that count as it stood when the refusal was decided, and the relay holds it until it has delivered
  as many. A refused statement adds no sync point of its own: nothing was forwarded, and honmoon
  supplies that `ReadyForQuery` itself, so the two counts stay in step. Two consequences follow:
  - **A refusal is no faster than the statements queued in front of it.** Refusing the second half
    of a pipelined pair means waiting out the first half's query. That is the point — the client
    asked in that order — but it makes a denial's latency a property of the client's own pipeline
    rather than of the policy engine.
  - **What is bounded is the stall, not the wait.** Every **backend message** that reaches the
    client buys another full 30-second window — the rows of a long result set included, not only
    the `ReadyForQuery` a refusal is actually waiting for. A database working steadily through a
    slow statement is therefore never cut off however long that statement runs; counting only sync
    points would have made a query streaming rows for longer than the window indistinguishable from
    one that had stopped, and injected the refusal into the middle of its result set. Only a pipeline that stops moving expires — which is
    what the two ways the count can go wrong look like from here: a database that stopped
    answering, and a sync point the backend swallowed (PostgreSQL ignores `Sync` while a `COPY` is
    in progress, so the `Sync` honmoon counted is never answered). An unbounded wait would cost the
    client its answer altogether, which is worse than the misattribution this removes, so the
    runtime warns and writes the answer anyway.

    The timer is the relay's own, around its own read of the upstream, because the relay is the task
    that knows whether any backend traffic arrived: "waiting on sync point N with nothing from the
    database for T" is one local decision rather than an inference from a counter another task
    publishes. What it gives up on is recorded **beside** what the client received rather than added
    to it. The relay keeps two numbers per side — how many answers it has really delivered, and how
    far a stalled wait has given up — and an answer is released once *either* reaches its tag. A gap
    is therefore never paid for twice (the counts only rise, so a skew left in place would make every
    later refusal on that connection pay the bound again for the rest of the session) while a
    delivered count that states only what the client actually holds cannot be falsified by an answer
    that turns up after all. The bounded quantity is the delivered `ReadyForQuery` count
    specifically; progress for the stall window is every backend message of any kind, and runs far
    ahead of it, since one query's sync point can carry thousands of rows.
  - **An answer that arrives after the relay gave up on it is counted where it belongs, and cannot
    be counted twice.** Giving up must not be recorded as the client having received something,
    because the database can still send it. An earlier design credited the delivered count and then
    had to remember the credit as **debt**, so that the next `ReadyForQuery` — which PostgreSQL's
    in-order answering makes the oldest unanswered statement's, a given-up one — paid the debt down
    instead of advancing the count. Without that, any statement forwarded in the meantime had raised
    the ceiling a late answer was checked against, so the stale answer fitted under it and was
    credited to a slot it did not own, releasing the refusal queued behind *that* statement before
    its response existed. Keeping the two numbers apart removes the need for that bookkeeping rather
    than making it cheaper: a late answer raises the delivered count truthfully, the give-up floor is
    unmoved by it, and a refusal tagged for a later statement is still measured against a tag neither
    number has reached.

    **This still costs a sync point that can never be answered more than one stall window.** A
    `Sync` swallowed during copy-in is given up on like any other, but no answer for it will ever
    arrive, so the delivered count stays where it is while every later statement raises the tag the
    next refusal is measured against — and each of those refusals pays a window too, not just the
    first. That is #128. The failure is latency, never ordering, which is the direction this section
    resolves every ambiguity in. Removing the cost needs the runtime to know a `Sync` was swallowed,
    which means tracking copy-in mode from the relay (the only task that sees the `CopyInResponse`)
    back into the message loop — a mechanism this ADR does not have.

    For a related reason a sync point is counted **before** the frame that earns it is forwarded,
    never after: a fast database can have its `ReadyForQuery` relayed to the client before the
    forwarding task runs its next line, and the relay's clamp — which is there so a backend cannot
    answer more sync points than it was asked for — would then throw away a perfectly good answer as
    an over-count, leaving the counts a permanent one apart. Counting early cannot be wrong: a sync
    point recorded for a write that then fails costs nothing, because the session ends with that
    write.
  - **A batch driven by `Flush` is ordered against a quiet upstream, not against a marker.**
    `Flush` makes the backend emit what it has buffered — `ParseComplete`, `BindComplete`, rows,
    `CommandComplete` — with no `ReadyForQuery`, so it is not a sync point. This ADR originally
    recorded that as unclosable and left such a batch unordered entirely, which meant a client
    using libpq pipeline mode read a refusal ahead of an earlier batch's responses exactly as it
    did before the barrier existed. #113 closed it, and this entry is amended rather than removed
    because what replaced it is weaker than the `Sync` guarantee and the difference matters.

    `Flush` frames are counted in a second counter of their own, and settled from the relay rather
    than by any frontend-predictable marker: a flush is drained once the relay has delivered a
    message the flush could have produced and then finds the upstream socket carrying nothing more
    at a message boundary. "Could have produced" is decided by excluding the backend messages that
    can never be the *last* of a flush's output — rows and copy data, the asynchronous
    `NoticeResponse`/`NotificationResponse`/`ParameterStatus` that a statement can emit while it is
    still running, the `ParameterDescription`/`RowDescription` that answer a `Describe` (a backend
    that has planned a query and not yet produced a row pauses right after `RowDescription`), and
    the messages that open or punctuate a copy. The list
    names what cannot end a batch rather than what always does, because the two ways of being wrong
    are not equal: a message wrongly treated as terminal releases a refusal into the middle of a
    statement's output, and one wrongly treated as non-terminal costs a stall window. The two counters stay separate because they are settled by different
    observations — one counter would let a sync point's answer settle a flush, and a quiet upstream
    settle a sync point the database is still computing.

    **A sync point settles the flushes that preceded it.** `ReadyForQuery` proves every frame
    before its `Sync` has been processed and its output emitted, so it subsumes every `Flush`
    already outstanding and is a stronger settlement than the quiet. It has to be, too: a batch
    ending `Flush`/`Sync` — what a libpq pipeline does at `PQpipelineSync()`, the commonest
    pipeline shape there is — comes back as one burst, so the relay sees no quiet before the `Z`
    and would otherwise leave that flush outstanding for a whole stall window. The count is
    snapshotted when the sync point is forwarded rather than read when its answer lands, because a
    `Flush` sent *after* a `Sync` is not answered by that `Sync`'s `ReadyForQuery`.

    Such an answer also settles a flush the relay had already given up on, turning the give-up into
    a real settlement: the answer proves the output was emitted, and it resets the relay's freshness
    count too, so no quiet for that batch can still be coming and the next one belongs to a later
    batch. Without that, the later batch would pay a stall window for output the client already
    has. Only the flushes the answer's coverage names are settled — it raises the delivered flush
    count to that coverage and no further — because a second batch can be given up on before the
    first sync point is answered, and that answer speaks for the earlier flush alone.

    **One quiet settles one flush, never every flush outstanding.** A quiet cannot say how many
    flushes it drained, and the two readings fail in opposite directions. A client may legitimately
    flush mid-batch (`Parse`/`Bind`/`Flush`/`Execute`/`Flush`, which is what `PQsendFlushRequest`
    is for), and there the backend answers the first flush and then goes quiet computing the
    `Execute`: crediting both flushes releases the refusal ahead of the rows, which is the defect
    this section exists to remove. Crediting one is wrong only when two batches' output reaches the
    relay as a single uninterrupted burst, and costs the next refusal one stall window before the
    relay gives up. The ambiguity is resolved toward waiting, for the same reason it is everywhere else
    here: the failure is latency, never ordering.

    **A flush the relay gave up on is recorded the way a given-up answer is, and for the same
    reason.** The flush side carries its own give-up floor beside its own delivered count, and the
    two sides' floors stay separate: crossing them would let a late `ReadyForQuery` answer for a
    flush, or a quiet upstream for a statement. What makes the separate record necessary is that the
    batch a wait gave up on can still produce its output afterwards, and by then the client may have
    sent another flushed batch — so a delivered count inflated by the give-up would be advanced by
    the quiet behind that late output into a slot belonging to a batch the database is still
    computing, releasing the refusal queued behind *that* one ahead of its rows.

    This inherits the sync side's recurring price too. A flush whose output never comes leaves the
    delivered count where it is while later flushes raise the tag, so every later refusal on the
    connection pays a stall window instead of only the first. The two cases are indistinguishable on
    the wire for the same reason they are on the sync side, and the ambiguity is resolved the same
    way.

    **What it still does not guarantee.** A burst split across TCP segments can leave the socket
    momentarily empty part-way through one batch's output, and a quiet read there settles that
    batch early. In the other direction, a batch whose output genuinely ends on an excluded message
    — a bare `Describe` of a row-returning statement, ending on `RowDescription` — is never settled
    by a quiet and costs the next refusal one stall window, or none at all when a `Sync` follows and
    answers for it. A `Flush` that elicits nothing at all — sent with no pending output, or ignored
    because a `COPY` is in progress — is never settled by the relay and costs the next refusal one
    `REFUSAL_ORDER_STALL_TIMEOUT` before the relay gives up on it, which a client can make itself pay
    repeatedly by sending a lone `Flush` before each denied statement. Closing the first needs the
    relay to wait out a grace period on every quiet: a second timing constant and a latency floor
    under every flush-driven refusal, which is a mechanism rather than a tweak and is tracked
    separately. Neither residual can forward a denied statement, and neither escapes the stall
    bound.
  - **A relay that stops partway through a message writes nothing more, because it no longer has a
    writer.** The client is left holding a frame header whose payload never arrived, so its stream is
    already desynchronised and it would read an injected `ErrorResponse` as that payload's
    remainder. A truncated connection is what the corruption already guaranteed, and adding bytes
    only makes the truncation unreadable. So the relay drops the client write half with itself, and
    the suppression needs no flag anybody checks: an answer queued at that moment is dropped with
    the channel, and one decided afterwards finds the channel closed. The earlier design had to
    decide this **under the client-writer lock** — mark the stream unframed while still holding the
    lock, and read the flag only after acquiring it — because a refusal that passed a check on the
    way in could acquire the lock afterwards and append itself to the partial frame. With one owner
    there is no lock to queue at and no window to close.
  - **A relay that stops on a message boundary writes what it is still holding, and hands the writer
    back.** Once the upstream→client task has ended, no further `ReadyForQuery` can arrive and there
    is nothing left to order against, so the answer the relay is holding goes out on a client socket
    that is still healthy — rather than being dropped when the session ends, which would hand the
    client the unexplained reset this whole answer exists to avoid. Handing the write half back
    covers the rest of that: the runtime races the message loop against the relay's exit **biased**
    toward the loop, so the loop can still decide a refusal after the relay has gone, and that
    answer is written with the half the relay returned. The relay returns one only when the client's
    stream is framed, so the same ownership that suppresses the corrupting case permits this one.
  - **The abandoned-hold courtesy notice budgets ordering and writing apart.** That notice already
    runs under a 5-second bound so a half-closed client cannot pin the session. The same half-close
    is what stalls the ordering wait, so the notice carries a deadline of its own — a 1-second slice
    of that budget — which the relay honours by writing it whether or not the client has received
    what it was owed: a stalled pipeline costs the notice its ordering, never the notice itself.
    Unlike the stall bound that deadline records no give-up; one answer surrendering its place is not
    the pipeline being declared dead.
- **A held statement is watched for its client's disconnect.** A `pause` verdict holds the
  statement mid-stream, which parks the client-read side of the session inside the `select!` the
  runtime races against its upstream relay — so a client that leaves completes neither arm and used
  to go unnoticed until `pause_timeout`, long enough for a human to approve a statement for a client
  that was already gone. The hold therefore takes an abandonment signal, and the runtime feeds it a
  read on the client socket. Bytes the client pipelined behind its held statement are buffered and
  handed back to the message loop rather than consumed. Three consequences follow:
  - **The watch cannot be flooded into switching itself off.** A client may pipeline up to
    `MAX_HELD_PIPELINE` (64 KiB) behind its held statement; past that the hold ends and the
    statement is **refused**. Parking the watch there instead would hand the client the threshold —
    flood past it, leave, and the hold runs to `pause_timeout` and can still be approved, which is
    the defect this whole mechanism exists to remove. Refusing rather than closing the socket keeps
    the session usable, as every other refusal here does. The cap is a sixteenth of the frame cap
    because every held connection can pin it at once: what has to stay bounded is the aggregate
    across the connection limit, not what one unusually generous client might pipeline.
  - **A client's half-close ends its hold.** The watch cannot tell a peer that closed its write half
    while still reading from one that is gone — both arrive as EOF — and reading EOF as "still
    waiting" would miss the ordinary disconnect, which is exactly what EOF is. So a client that
    shuts down its write half while one of its statements is held loses that statement, where an
    unheld one would still have been answered under the drain. It is told so: the runtime writes the
    usual `ErrorResponse`/`ReadyForQuery` pair before ending the session, so a client that is still
    reading gets an explanation rather than a truncated connection. That write is bounded: a client
    that half-closed and then stopped reading must not be able to pin the session open by refusing
    to accept its own answer.
  - **A decision in hand beats a simultaneous disconnect.** The hold polls its decision channel
    first and, when the abandonment signal wins, checks that channel once more before giving up. A
    resolution that lands between those two polls is still honoured, so the audit log does not
    record an abandonment over an approval a human really made.
- Inspection costs one buffered copy per statement, bounded at 1 MiB. Bulk paths (`COPY`) stay
  zero-copy, which is where the bytes actually are.
