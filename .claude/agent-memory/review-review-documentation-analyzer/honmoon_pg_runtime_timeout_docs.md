---
name: honmoon-pg-runtime-timeout-docs
description: honmoon documents PostgreSQL runtime internal timeouts (DRAIN_TIMEOUT, pause_timeout, REFUSAL_ORDER_STALL_TIMEOUT) in ADR-0007's Consequences, not in README — established precedent, not an omission to flag
metadata:
  type: project
---

`crates/honmoon-proxy/src/runtime/postgres.rs` has several internal timing constants
(`DRAIN_TIMEOUT` = 30s, `pause_timeout`, and as of PR #112 `REFUSAL_ORDER_STALL_TIMEOUT` = 30s) that
bound how long a client can wait for a response. None of these appear in `README.md`'s "SOCKS5
and inline PostgreSQL inspection" section — the project's established pattern is to document this
class of operational detail (what bounds a wait, what happens when the bound expires) in
[[honmoon-adr-0007-postgres-barrier]] ADR-0007's Consequences section, referenced from the README
via a link, rather than duplicating timeout values into user-facing prose.

**Why:** Checked while reviewing PR #112 (pipelined-refusal ordering barrier, `REFUSAL_ORDER_STALL_TIMEOUT`).
The new 30s bound and its "warns and injects, degrades to old ordering" failure mode are documented
only in the ADR amendment, matching how `DRAIN_TIMEOUT` and `pause_timeout` were already handled —
so treat this as the repo's convention, not a gap.

**How to apply:** Don't flag a PostgreSQL-runtime timeout constant for being undocumented in
README/user-facing docs as long as it's covered in ADR-0007's Consequences and the README already
links to that ADR. Only flag if the ADR itself is missing the detail, or if the ADR and code
diverge on the bound's value or failure behavior.
