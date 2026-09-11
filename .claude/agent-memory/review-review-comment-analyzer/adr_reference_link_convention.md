---
name: adr-reference-link-convention
description: honmoon-proxy has two competing conventions for citing ADRs in rustdoc comments; new code should follow the linked one
metadata:
  type: project
---

`crates/honmoon-proxy/src/` has two coexisting conventions for citing `.please/docs/decisions/*.md`
ADRs from rustdoc comments:

1. **Linked** (`gateway.rs`, `socks.rs`): `[ADR-0003]` inline, with a reference-link definition
   `[ADR-0003]: ../../../.please/docs/decisions/0003-....md` elsewhere in the module doc. Resolves
   as a clickable link in generated rustdoc.
2. **Bare text** (`signed_body.rs`, and as of PR #150 also `body.rs`/`mitm.rs`): `ADR-0006` or a
   literal `` `.please/docs/decisions/0009-....md` `` path with no link definition. Renders as
   inert text, not a link, and doesn't need the `../../../` relativity the linked form requires.

**Why:** noticed while reviewing PR #150 (issue #133) — the new body-only-inspection-contract
comments in `body.rs`/`mitm.rs` cite ADR-0009/ADR-0006 as bare paths, which is *consistent with*
`signed_body.rs`'s existing precedent but *inconsistent with* `gateway.rs`/`socks.rs`'s link
convention. Not a factual defect (the paths do resolve, ADR-0009 exists), just an unresolved style
split in the crate.

**How to apply:** when reviewing new ADR citations in `honmoon-proxy/src/`, flag the mismatch as
low-severity/style rather than accuracy — do not treat either convention as authoritative since the
crate itself hasn't picked one. If asked to unify it, the linked form is the one that produces
working rustdoc output.
