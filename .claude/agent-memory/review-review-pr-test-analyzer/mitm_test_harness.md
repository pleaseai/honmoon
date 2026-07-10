---
name: mitm-test-harness
description: honmoon-proxy's MITM integration test harness (tests/mitm.rs) cannot observe forwarded/upstream bytes — relevant when reviewing detect-only forwarding claims
metadata:
  type: project
---

`crates/honmoon-proxy/tests/mitm.rs`'s `rrn_audited_for` harness uses
`start_dropping_upstream()` — a TCP listener that accepts and immediately
drops the connection, so the proxy's upstream TLS handshake fails fast (502).
This is deliberate: it keeps the test hermetic and avoids standing up a second
TLS server for the "upstream" leg.

**Consequence**: none of the `tests/mitm.rs` integration tests can assert what
bytes the proxy actually forwards upstream — only what lands in the audit log
(PII findings). Any "detect-only: original bytes forwarded unchanged" claim in
`src/mitm.rs`'s doc comments (this is a load-bearing invariant, stated
explicitly in the module doc and in `decode_for_inspection`'s doc comment) is
therefore backed by *reading the code*, not by a forwarding-content test.

**Why it matters for review**: `crates/honmoon-proxy/src/mitm.rs`'s
`inspect_body` (around line 280-372) deliberately splits `scanned` (raw bytes,
used to build `new_body` for forwarding) from `decoded` (decompressed bytes,
used only for `detect_pii`). A future refactor that accidentally forwards
`decoded` instead of `scanned`/original bytes for a gzip/deflate body would
corrupt outbound requests (body no longer matches its `Content-Encoding`
header) — and no existing test would catch it, unit or integration.

**How to apply**: when reviewing changes to `inspect_body` or
`decode_for_inspection` in `crates/honmoon-proxy/src/mitm.rs`, check whether
forwarding-content coverage was added (e.g. a working echo/capturing upstream
instead of `start_dropping_upstream`) before treating "original bytes forward
unchanged" as verified by tests rather than by code reading alone. See
[[pii-detect-only-invariant]] for the general pattern (detect-only PII
scanning splits scan-input from forward-output) if that memory exists yet.
