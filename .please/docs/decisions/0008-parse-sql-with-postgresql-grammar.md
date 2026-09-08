# ADR-0008: Classify SQL with PostgreSQL's grammar, not a token heuristic

## Status

Accepted

## Context

ADR-0007 put `parse_sql` and `carries_multiple_statements` on a live socket. Both were
hand-rolled text scanners: `parse_sql` took the first whitespace-delimited token as the verb,
and `carries_multiple_statements` walked bytes looking for a `;` outside a literal, quoted
identifier, dollar-quoted body or comment.

Review of the runtime found defects in those two functions in six consecutive rounds. Several were
exploitable rather than merely annoying: a `$tag$`-quote bypass, a CR-only line ending that hid a
second statement, a non-ASCII identifier byte that reopened the first of those after it had been
fixed, a comment prologue that masked the verb, and — reaching a dangerous operation while the
facts reported a harmless verb, so a `sql.verb == 'DELETE'` deny rule never fired — `WITH x AS
(DELETE …) SELECT …`, `EXPLAIN ANALYZE DELETE …`, and `WITH x AS (MERGE … THEN DELETE …)
SELECT …`. The rest were false refusals of ordinary traffic. The pattern matters more than the
tally: each fix was correct, and each was followed by another instance of the same class.

The reason patching kept failing is that the correctness condition here is not "usually right".
honmoon has to agree with PostgreSQL about two things — where a statement ends, and what a
statement executes — under input an attacker chooses. That is exact agreement with a specific
grammar, which is a parser's job and not a heuristic's. A scanner can be made to pass any finite
set of adversarial examples and still lose to the next one.

Two categories of hole made this concrete:

- **Lexical.** PostgreSQL's `scan.l` rules for `ident_cont`, dollar quoting, `E'…'` escapes and
  `--` comment termination all have to be reproduced exactly, including their treatment of bytes
  `>= 0x80`.
- **Grammatical.** A statement's leading keyword does not say what it runs. `EXPLAIN ANALYZE`
  executes what it wraps; a data-modifying CTE executes inside an outer `SELECT`. No amount of
  token inspection sees these, because the information is structural.

## Decision

**Parse with `sqlparser`'s `PostgreSqlDialect`.** The workspace dependency was approved
explicitly, per the ask-first rule in `crates/AGENTS.md`. It is pure parsing with no I/O, so
`honmoon-core` stays transport-agnostic.

**Classify by what a statement executes, not by what it starts with.** `EXPLAIN ANALYZE` and
`EXPLAIN (ANALYZE, …)` are unwrapped to the statement they run; a plain `EXPLAIN` is not, because
it only plans. `EXPLAIN (ANALYZE [ boolean ])` takes a value, and it is honoured — but only an
argument that is *explicitly* false turns execution off. A bare `ANALYZE`, `ANALYZE true`, and any
argument shape the code does not recognize all count as executing, because this is the one
judgement in the classifier whose failure mode is a bypass rather than a refusal. Data-modifying
CTEs outrank the outer `SELECT`. Where several verbs execute, the most dangerous one is reported,
ordered once in `VERB_PRECEDENCE`
(`DROP > TRUNCATE > ALTER > MERGE > DELETE > UPDATE > INSERT > SELECT`). The ordering is
deny-oriented on purpose: under-reporting a verb is a bypass, while over-reporting one can only
refuse something. `MERGE` outranks each of `DELETE`/`UPDATE`/`INSERT` because a single `MERGE`
can perform all three.

**Statement boundaries come from the parser.** `carries_multiple_statements` returns
`statements.len() > 1`, which is exact rather than conservative on anything the grammar reads.

**What cannot be inspected is refused, not classified.** A `DO` block runs an arbitrary PL/pgSQL
body while reporting the harmless verb `DO`, and there is nothing to unwrap — the body is not SQL,
and sqlparser has no `DO` statement at all. It is refused at the runtime, the same fail-closed
path already taken for a batched or unparseable frame. Because the parser cannot see `DO`, this is
the one place left that identifies a statement outside the grammar, and it therefore follows
PostgreSQL's lexical rules directly rather than splitting on whitespace: a comment is whitespace to
the server, so `DO/**/$$…$$` executes, and reading the keyword as an identifier run is what keeps
honmoon's answer identical to the server's in both directions — including `DO$$…$$`, which is one
identifier to PostgreSQL and rejected by it. `CALL`, `EXECUTE` and `COPY` raise the same question
for different reasons and are tracked in #103; whether to refuse them changes what honmoon does to
ordinary traffic, so it is deliberately not settled here.

**A statement naming several relations reports no table.** `SqlFacts` carries one `table`, so for
`DROP TABLE scratch, users` no single value is correct — and reporting the first is wrong in the
dangerous direction, because an allow rule scoped to `sql.table == 'scratch'` would then authorize
dropping `users` alongside it. The verb is still reported, so verb-only rules are unaffected;
only table-scoped rules stop matching, which leaves the statement to a table-blind decision.

**Both prior scanners are kept as the fallback for input the parser rejects**, as
`parse_sql_heuristic` and `scan_for_statement_separator`. This is the load-bearing part of the
decision, not a leftover: it bounds the cost of adopting a parser. On any input sqlparser cannot
read, behaviour is exactly what shipped before it, so no path through either function is more
permissive than the scanners alone, and a query the parser merely fails to understand is not
newly refused.

## Consequences

- **False refusals are bounded, not eliminated.** A statement the parser rejects falls back to the
  old behaviour rather than being denied, so the usual cost of adopting a strict parser does not
  apply. What remains is that the parser's idea of PostgreSQL is not PostgreSQL's: syntax it
  models differently is classified differently. `DROP INDEX CONCURRENTLY` is one such input today
  and is covered by a test pinning the fallback.
- **Table extraction is now grammatical rather than positional, and therefore different.** The
  heuristic took the token after the first `FROM`/`INTO`, which was wrong whenever that keyword sat
  inside a subquery, a `USING` clause, or a table function. The new values are correct, but a rule
  keyed on an old wrong table stops matching. `ALTER TABLE` now carries its table, where it
  previously carried none.
- **`WITH … SELECT` over read-only CTEs now reports `SELECT`, not `WITH`.** A `sql.verb == 'SELECT'`
  rule matches queries it previously missed — an added match on read rules, so a deny-reads policy
  tightens.
- **The same `Q` payload is parsed twice**, once by `carries_multiple_statements` and once by
  `parse_sql`. Accepted for now; the data plane has a frame size cap (ADR-0007) that bounds the
  input, and merging the two would change the public surface `honmoon-proxy` depends on.
- **Data-modifying CTEs nested below the top level need no handling.** PostgreSQL rejects them
  itself (`ERROR: WITH clause containing a data-modifying statement must be at the top level`,
  verified against 17.11), so a nested `WITH … DELETE` inside a derived table or scalar subquery
  never executes and does not need to be classified.
- **Client encoding remains out of reach, and is the known limit of this decision.** Under a
  client encoding that is not ASCII-compatible (SJIS, BIG5, GBK, UHC), a multibyte character's
  trailing byte can be below `0x80` and collide with `$`, `'` or `-`. honmoon forwards the
  encoding in the StartupMessage parameters verbatim and the client can change it later with
  `SET client_encoding`, so the bytes honmoon scans are not necessarily the characters the server
  lexes. Parsing does not fix this — it is an encoding problem, not a grammar one — and closing it
  means tracking the session's encoding and decoding before parsing.

## What `sql.table` and `sql.verb` cannot promise

Parsing settles what the *statement text* says. It cannot settle what the *database* will do with
it, because some of that lives in the catalog rather than in the message honmoon is holding. These
are limits of the facts, not defects to be fixed later, and a policy author needs them stated:

- **A view hides the relations behind it.** `SELECT * FROM reporting_v` reports `reporting_v`, and
  the view may select from `secrets`. Paired with `CREATE OR REPLACE VIEW v AS SELECT * FROM
  secrets`, which reports only the verb `CREATE`, this is a durable read-path launder that no
  parser can see: the definition is server-side and the read happens later under a different
  statement.
- **Inheritance and partitioning widen a read silently.** `SELECT * FROM parent` also reads every
  child table, and which tables those are is catalog state.
- **A function body is opaque.** `SELECT drop_everything()` reports `SELECT`, and a `VOLATILE`
  function can perform arbitrary DML. `CALL` and `EXECUTE` are the same shape and are tracked in
  #103.
- **A statement may read relations it does not write.** `UPDATE a SET … FROM b`,
  `DELETE FROM a USING b` and `INSERT INTO a SELECT … FROM b` all report the write target
  correctly and leave the read source unnamed.

The practical consequence: **`sql.table` is dependable for naming what a statement writes, and is
not a complete account of what it reads.** A policy that must confine reads should not rest on
`sql.table` alone — restrict the endpoint, or use database-side privileges, where the catalog is
actually visible. Where honmoon can tell that a statement touches more relations than it names, it
now reports no table rather than a misleading one, so a table-scoped allow cannot be tricked into
authorizing an unnamed relation; that is a guard against being wrong, not a claim to completeness.

Representing the full set instead of one relation — `SqlFacts { tables: [...] }`, with rules
written as `'users' in sql.tables` — would recover the expressiveness that reporting nothing gives
up. It is not done here because it changes the policy struct, which is ask-first under
`crates/AGENTS.md` and has to stay in sync with the TypeScript types and JSON Schema (TD-001).

## Alternatives Considered

- **Keep patching the scanners.** Rejected because six rounds of it had already been tried. Each
  round's fix was correct and each was followed by another instance of the same class, including
  one fix that regressed an earlier one in the same function. It also cannot reach the
  grammatical holes at all: no token inspection sees that `EXPLAIN ANALYZE` executes its argument,
  because that fact is structural rather than lexical.
- **Fail closed on any verb the classifier cannot recognize.** Rejected because it addresses only
  the verb-classification half. The statement-boundary scanner is still required under this
  option, so the lexical bypasses (`$tag$`, CR line endings, non-ASCII `ident_cont`) survive
  untouched. It also refuses ordinary traffic — `SET`, `BEGIN`, `COMMIT`, `VACUUM` — so operators
  would have to allow-list the normal operation of their own sessions.
- **Refuse any `Q` carrying a top-level `;` at all**, dropping the single-trailing-semicolon
  allowance. Rejected for the same reason: it is a statement-boundary measure that leaves verb
  classification exactly as it was, and it breaks `SELECT 1;`, which essentially every client
  sends.
- **Ship with the wrapper bypasses filed as issues and the runtime marked experimental.**
  Rejected because the bypasses are live in a security control: a `sql.verb == 'DELETE'` rule that
  silently does not fire is worse than an absent feature, since the operator believes the rule is
  in force. "Experimental" in a README does not change what the data plane does.
- **Write a PostgreSQL-compatible lexer in-house** rather than take a dependency. Rejected on
  cost-to-correctness: matching `scan.l` exactly, including its handling of bytes `>= 0x80`, is
  the same work `sqlparser` has already done and is tested against, and the six rounds are
  evidence about how well hand-rolled scanning was going.
