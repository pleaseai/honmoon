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
- **A local answer is injected in request order, not just on a frame boundary.** Honmoon writes
  its `ErrorResponse`/`ReadyForQuery` into a stream the upstream→client relay is writing at the
  same time. Framing that injection is not enough on its own: a client that pipelines
  `SELECT pg_sleep(1); DROP TABLE users;` would read the refusal for the `DROP` before the
  `SELECT`'s response and attribute the 42501 to the statement that in fact succeeded — a firewall
  telling the truth about the wrong query. So the runtime counts **sync points**: the completed
  startup handshake, then every `Q`, `Sync` and `FunctionCall` it forwards, each of which the
  database answers with exactly one `ReadyForQuery`. A refusal waits until the relay has delivered
  that many before it takes the writer lock — and waits *before* taking it, because the relay needs
  the same lock to deliver the responses being waited for. A refused statement adds no sync point
  of its own: nothing was forwarded, and honmoon supplies that `ReadyForQuery` itself, so the two
  counts stay in step. Two consequences follow:
  - **A refusal is no faster than the statements queued in front of it.** Refusing the second half
    of a pipelined pair means waiting out the first half's query. That is the point — the client
    asked in that order — but it makes a denial's latency a property of the client's own pipeline
    rather than of the policy engine.
  - **What is bounded is the stall, not the wait.** Every response that reaches the client buys
    another full 30-second window, so a database working steadily through a slow statement is never
    cut off however long that statement runs. Only a pipeline that stops moving expires — which is
    what the two ways the count can go wrong look like from here: a database that stopped
    answering, and a sync point the backend swallowed (PostgreSQL ignores `Sync` while a `COPY` is
    in progress, so the `Sync` honmoon counted is never answered). An unbounded wait would cost the
    client its answer altogether, which is worse than the misattribution this removes, so the
    runtime warns and injects. It also **writes the missing answers off** rather than leaving the
    counters skewed: they are monotonic, so a gap left in place would make every later refusal on
    that connection pay the bound again for the rest of the session.
  - **A batch driven by `Flush` is not ordered at all.** `Flush` makes the backend emit what it has
    buffered — `ParseComplete`, `BindComplete`, rows, `CommandComplete` — with no `ReadyForQuery`,
    so it is not a sync point and honmoon counts nothing for it. A client using libpq pipeline mode
    can therefore still read a refusal ahead of an earlier batch's responses, exactly as it did
    before this barrier. The protocol offers no marker for "the backend has finished flushing", so
    counting cannot close this the way it closes `Sync`; it is recorded here rather than implied
    away, and tracked separately.
  - **A relay that stops releases the wait immediately.** Once the upstream→client task has ended,
    no further `ReadyForQuery` can arrive and there is nothing left to order against. The wait
    therefore ends the moment the relay does, so the refusal is written on a client socket that is
    still healthy — rather than being cancelled unwritten when the relay's exit ends the session,
    which would hand the client the unexplained reset this whole answer exists to avoid. Releasing
    the wait is only half of that: the same exit also readies the future the runtime races the
    message loop against, so the race is **biased** toward the loop. Otherwise the two become
    ready together and an unbiased choice discards the refusal about half the time, which is the
    reset again by a narrower path.
  - **The abandoned-hold courtesy notice budgets ordering and writing apart.** That notice already
    runs under a 5-second bound so a half-closed client cannot pin the session. The same half-close
    is what stalls the ordering wait, so the wait is capped at a 1-second slice of that budget and
    the rest is reserved for the write: a stalled pipeline costs the notice its ordering, never the
    notice itself.
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
