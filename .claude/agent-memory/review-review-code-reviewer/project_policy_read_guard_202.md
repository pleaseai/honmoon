---
name: project-policy-read-guard-202
description: 'PR #217 (issue #202) lifted not_a_policy_document into load_policy so run/gateway/policy validate share it; load_policy now returns (Policy, String) — reviewed clean, plus the exhaustive argument for "no verdict moved"'
metadata:
  type: project
---

PR #217 (issue #202) moved `not_a_policy_document` from `policy_validate` into
`load_policy` in `crates/honmoon-cli/src/main.rs`, and `load_policy` now returns
`(Policy, String)` because `gateway` hands the source text to the management API,
which serves it verbatim at `GET /api/policy` for the dashboard's read-only policy
view. (Not the Claude Code hook endpoint — nothing there reads `policy_yaml`; the
constructor `AppState::with_hook_config` is named for the salt argument beside it,
and an early version of the PR's own doc comment got this wrong.) 3 call sites only
(gateway, run, policy_validate), tests and `clippy --all-targets` green.

**Read this next to what a code-quality pass did *not* catch on that PR.** The same
review round's silent-failure and test finders both found a live leak in the guard's
deferral arm — a multi-document file let serde quote a whole plain-scalar document —
which a call-site-and-verdict review missed entirely because it is a property of the
downstream parser's *message*, not of the control flow. See
[[policy-guard-multidoc-scalar-escapes]].

**Why:** the leak is a property of the read, not of one subcommand — serde renders a
top-level mismatch as `invalid type: string "<value>"`, and YAML folds a multi-line
plain scalar into one, so the quoted value is the whole file.

**How to apply:** on any future change to this guard, the "no verdict moved" claim is
settled exhaustively over `serde_yaml::Value`'s variants, not by the test's sample
list: `Mapping`/`Null` pass, `Sequence`/`String`/`Bool`/`Number` are refused and a
struct deserialize refuses them too, and `Tagged` recurses (serde looks through a tag,
so refusing tagged nodes would refuse a policy the gateway runs — that was a real bug
once). A parse failure returns `None` on purpose, deferring to serde's positional
syntax error. The stated bound — a *mapping* with a mistyped field value still reaches
`version: "<…>"` — is deliberate, so do not report it as an unfixed leak; it is pinned
by `a_documented_bound_still_reaches_the_loader`. Since all three commands now run the
guard, cross-command parity tests no longer witness the claim; `Policy::from_yaml` is
the only independent witness left.

The guard classifies the **first document** of the file, not the stream, and that is
load-bearing rather than incidental: `serde_yaml::from_str::<Value>` refuses a
multi-document stream instead of returning its first document, so a stream-level check
deferred every file carrying a `---` line straight into the leak. A parse failure of
that first document still returns `None` on purpose, deferring to serde's syntax
diagnostic — which names what it stopped on rather than reproducing the document, and
carries a position only once the scanner is past the start.
