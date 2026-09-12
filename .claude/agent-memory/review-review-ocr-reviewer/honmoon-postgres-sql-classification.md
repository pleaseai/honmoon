---
name: honmoon-postgres-sql-classification
description: How to verify honmoon-core's sqlparser-based SQL verb classification claims against real PostgreSQL (local psql/initdb available) — hypothesize accepted-but-unwalked AST shapes and check them before reporting — and where it already covers itself
metadata:
  type: project
---

`crates/honmoon-core/src/protocols.rs` classifies SQL statements (sqlparser 0.62,
PostgreSqlDialect) to drive `sql.verb`/`sql.table` policy facts consumed by
`crates/honmoon-proxy/src/runtime/postgres.rs`. This code has already been through
six review rounds / ten fixed defects before the sqlparser rewrite landed (PR #89,
issue #86), so a naive re-read rarely finds new bugs — the fruitful technique is to
hypothesize an AST shape sqlparser accepts that the classifier doesn't walk into
(e.g. `Statement::Insert.source: Query` carrying its own `WITH` — a data-modifying
CTE nested in the INSERT's own source rather than the statement's top-level
`with`), and then check whether **real PostgreSQL** actually accepts that syntax.

**Verified false positive**: `INSERT INTO t (a) WITH y AS (DELETE FROM t2
RETURNING id) SELECT id FROM y` parses fine under sqlparser (source Query has its
own `with`), but real PostgreSQL rejects it with `ERROR: WITH clause containing a
data-modifying statement must be at the top level` — same restriction applies with
or without an explicit column list. So the classifier's silence on `insert.source`
is not a bypass: nothing dangerous can hide there. Local Postgres for this kind of
check: `/usr/local/bin/initdb`/`pg_ctl`/`psql` are present on this machine (no
docker needed) — `initdb -D <dir> -U postgres -A trust`, `pg_ctl -D <dir> -l
<log> -o "-p 55432 -k /tmp" start`, then `psql -h /tmp -p 55432 -U postgres -d
postgres`. Always test the *exact* candidate bypass string against real Postgres
before reporting it as a finding — sqlparser is deliberately more permissive than
Postgres's own grammar in places, and the classifier's authors already lean on
that "Postgres itself refuses it" backstop (documented explicitly in code
comments) rather than re-deriving the top-level-CTE rule themselves.

See [[ocr-scoping-honmoon]] for how Delegation Mode was invoked on this repo.
