# Track: Phase 2 — CEL evaluator + HTTP facts

## Goal

Make Honmoon's policy engine protocol-aware: evaluate `Rule.condition` (CEL) over
structured `Facts`, layered above the Phase 1 egress domain lists.

## Functional requirements

- FR1: Integrate a CEL evaluator (`cel-interpreter`) in `honmoon-core`.
- FR2: `decide(policy, facts)` evaluates rules in order; the first rule whose `endpoint`
  matches and whose CEL `condition` is `true` wins; otherwise fall back to egress lists.
- FR3: Expose `HttpFacts` (`method`, `host`, `path`, `body_size`) to CEL as `http`.
- FR4: Consolidate the policy engine in `honmoon-core` (move domain matching out of `honmoon-proxy`).
- FR5: Fail-closed — a rule that fails to compile or references unknown facts does not match.

## Acceptance criteria

- AC1: CEL rule `http.method == 'POST'` denies a POST fact, passes otherwise.
- AC2: `endpoint` gates rule applicability (`*` = any; else exact).
- AC3: Egress allow/deny/default still behave as in Phase 1 (deny wins over allow).
- AC4: Unknown fact reference (`sql.*`, not yet provided) → no match (no panic).

## Out of scope

- Populating HTTP method/path/body from real traffic (needs TLS termination — later phase).
- SQL/K8s facts (Phase 3).
