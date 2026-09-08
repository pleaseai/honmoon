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
- **A `postgres` endpoint is gated per statement, not per connection.** The egress lists do not
  decide the connection itself; the rules decide each query. A policy that wants to keep clients
  off a database entirely should not declare it as an endpoint.
- Inspection costs one buffered copy per statement, bounded at 1 MiB. Bulk paths (`COPY`) stay
  zero-copy, which is where the bytes actually are.
