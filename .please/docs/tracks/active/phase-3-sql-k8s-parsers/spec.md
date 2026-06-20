# Track: Phase 3 — Protocol awareness (SQL / K8s)

## Goal

Parse non-HTTP protocols at the wire level into structured `Facts` so CEL rules
can govern database and Kubernetes actions — the product's moat.

## Functional requirements

- FR1: PostgreSQL simple-query (`'Q'`) parser → `SqlFacts{verb, table}` (`parse_postgres_query`).
- FR2: SQL verb/table heuristic over a statement (`parse_sql`) for DROP/TRUNCATE/DELETE/UPDATE/INSERT/SELECT.
- FR3: Kubernetes API parser (`parse_k8s_request`) → `K8sFacts{verb, resource, namespace}`,
  for core (`/api/v1`) and grouped (`/apis/{group}/{ver}`) paths, list-vs-get from the path shape.
- FR4: Expose `sql`/`k8s` to CEL; bind rules to endpoints via `Rule::endpoint`.

## Acceptance criteria

- AC1: A PostgreSQL `DROP`/`TRUNCATE` on `postgres-prod` → `pause` (matches `sql-no-prod-drop`).
- AC2: A `DELETE` on a `secrets` resource on `k8s-prod` → `deny` (matches `k8s-no-secret-delete`).
- AC3: The shipped `policies/agent.yaml` rules fire for the parsers' output (drift guard).
- AC4: Malformed PostgreSQL packets are rejected (`None`), not panicked on.

## Out of scope (→ TD-006)

- Live inline TCP relay feeding the parsers from real sockets (per-endpoint listeners).
- TLS termination for the Kubernetes HTTPS API.
