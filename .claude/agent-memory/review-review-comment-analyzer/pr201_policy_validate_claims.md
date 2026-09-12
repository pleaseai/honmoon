---
name: pr201-policy-validate-claims
description: "In crates/honmoon-cli the doc comments are falsifiable claims naming a call graph, so check them mechanically; on PR #201 every call-graph claim held and the one that failed was a narrow guarantee stated generally"
metadata:
  type: project
---

`crates/honmoon-cli/src/main.rs` is written with unusually dense, verification-oriented doc
comments — the author states what the code does **not** reach, and names the callee. That is
the shape this repo has been bitten by before ([[guard-unnecessary-doc-comment]]), so it earns
tracing rather than skimming. The tracing is mechanical: grep the callee, read the guard, run
the test.

**On #201 (`honmoon policy validate`, issue #198) every call-graph claim held.**
`policy_validate`'s "no mgmt token resolved, no audit log opened, no CA read or generated, no
listener bound" is true because all four live inside `gateway()`, which it never calls.
`init_tracing`'s "every command keeps the historical ERROR default" is true **of the
commands it is about**, and the exception is the point of the change: `policy validate`
moved from `ERROR` to `WARN`, so the loader's two `tracing::warn!` diagnostics reach the
operator. `run`, `gateway` and `hook` are untouched, and for them the new spelling is the
old behavior written out — `EnvFilter::from_default_env()` in tracing-subscriber 0.3.23 *is*
`builder().with_default_directive(LevelFilter::ERROR).from_env_lossy()`. Do not carry away
"tracing was untouched": a `policy` command's default level and its writer (stderr, not the
fmt default stdout) both changed.

**The claim that did fail was a different shape, and that is the lesson.** The comment said a
load failure "names every offending rule (#197)". True of `validate_compiled_conditions`,
which collects every uncompilable condition — and false of the loader's other checks, which
`return` on the first offender (`validate_endpoints`, `validate_rules` in
`crates/honmoon-core/src/lib.rs`). A narrow guarantee had been restated as a general one, and
it read as settled because the narrow version was true and cited a PR. It had been copied into
three places (`--help`, the README, the wiki table) before anyone checked, and #201 fixed all
three.

**How to apply:** when a comment cites a specific function or PR for a guarantee, check that
the guarantee's *scope* is the cited thing's scope. A claim quantified over "every X" beside a
citation covering one code path is the one to open. Tracing a "does not reach" claim is cheap
and usually confirms; tracing a "covers everything" claim is where the finding is. Same family
as [[docs-completeness-claim-unbounded-review]] if that note exists in your index.
