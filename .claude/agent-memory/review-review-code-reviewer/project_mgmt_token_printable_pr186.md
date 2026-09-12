---
name: project-mgmt-token-printable-pr186
description: 'PR #186 (issue #173) mgmt_token.rs — Source::printable() echoed the persisted token on every restart; FIXED in that PR by also requiring stderr to be a terminal, so do not re-report it'
metadata:
  type: project
---

`crates/honmoon-cli/src/mgmt_token.rs`'s `Source::printable()` returns `true` for both
`Generated` and `Persisted` (only `Operator` is non-printable), so `main.rs`'s startup banner
echoed the `login?token=...` URL on *every* restart that read an already-persisted token, not only
the run that minted it. The module's own doc comment justifies never echoing an `Operator` token by
naming "a supervisor shipping stderr to a log aggregator" as an exposure the operator did not
choose — and that is exactly the supervisor receiving the persisted token on every restart.

**FIXED in #186 — do not re-report.** `printable()` is unchanged (it still answers "is this
honmoon's own token"), and the banner now additionally requires `std::io::stderr().is_terminal()`
before printing the token. A terminal is a person about to click the link; a pipe is a journal or
an aggregator. When stderr is redirected the banner names the token *file* instead, so the
operator can still find the credential, and the path is printed either way.

**How to apply:** if this file or the banner changes, the property to preserve is that the token
reaches a terminal and never a pipe — not that `printable()` has any particular shape. The
neighbouring rule from the same review: the token must not reach argv either, since `ps` is
readable by every local user (the run-honmoon driver passes `HONMOON_MGMT_TOKEN`).
