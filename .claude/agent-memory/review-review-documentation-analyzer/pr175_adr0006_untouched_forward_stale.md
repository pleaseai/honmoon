---
name: pr175-adr0006-untouched-forward-stale
description: 'An unconditional pre-decision transform falsifies absolute "untouched/byte-identical/verbatim" promises in documents the diff never touches — grep the whole repo for them, not just the ADR the change is about'
metadata:
  type: feedback
---

PR #175 (issue #134) added `trailer_filtered_body` in `crates/honmoon-proxy/src/body.rs`,
wrapping the forwarded body at the single convergence point in `mitm.rs::inspect_body` —
before `decide_explained` runs and before `forwarded_request`, where ADR-0006's
`--signed-body forward`/`block` decision lives. The wrap is unconditional, so every
request reaching `forwarded_request` already carries the filtered body, including a
body-signed request under `forward` and a request with nothing to redact.

The PR's first round correctly amended the two documents whose job is to state the *new*
behavior — README's wire-redaction trailer paragraph and ADR-0009. It missed a **third**
document and a **second** README location that stated an older, now-contradicted absolute
promise the diff never touched:

- `.please/docs/decisions/0006-signed-body-requests-under-wire-redaction.md`: "`forward`
  returns the original request untouched — same bytes, same headers"; "forwarded
  byte-identical and logs nothing".
- `README.md`'s signed-body section: "always forwarded untouched".

**Both were amended before PR #175 merged** — ADR-0006 gained a `#134` Status amendment and
an explicit "the one thing `forward` does not reproduce verbatim" subsection, and README's
sentence gained the exception. Do **not** re-flag them as unamended; read them at HEAD.

**Why:** same class as [[pr150_adr0009_body_only_contract]] — a stated guarantee the code
does not keep — but the instructive twist is *where* it hid. The documents a PR amends are
the ones its author is already thinking about; the stale claim lives in the document nobody
opened.

**How to apply:** when a change adds an unconditional transform *upstream* of a documented
decision point, grep the whole repository for absolute promises about that same data path
(`untouched`, `byte-identical`, `verbatim`, `unchanged`, `always forwarded`) rather than
reviewing only the documents in the diff. Then check whether the promise is scoped to the
mechanism its own ADR describes, or stated flatly — a flat one is now false.
