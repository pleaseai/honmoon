---
name: policy-guard-multidoc-scalar-escapes
description: "A test whose name asserts a universal property over one fixture hides the shapes it does not reach — honmoon's no-quoting test passed while a multi-document YAML file still leaked from all three commands (PR #217 closed the leak and widened the fixtures)"
metadata:
  type: project
---

`not_a_policy_document` (`crates/honmoon-cli/src/main.rs`) classified shape with
`serde_yaml::from_str::<serde_yaml::Value>(src)` and deferred on any parse error
(`Err(_) => None`). Multi-document input *is* a parse error for `Value`, but
`Policy::from_yaml` reports the first document's type mismatch first — so a PEM
block followed by a `---` line still printed
`invalid type: string "<first document, folded>"` from all three of
`policy validate`, `run --policy` and `gateway --config`. Measured on the PR #217
binary (2026-09-14). A *mapping* first document did not leak.

**Why the tests missed it.** `no_command_that_loads_a_policy_by_path_quotes_the_file`
asserted a universal property in its name over a single-document fixture, and the
two-loop structure of `every_shape_the_guard_refuses_is_one_the_loader_refuses_anyway`
could not express the deferral arm at all: there the guard returns `None` while
the loader returns `Err`, which fits neither "guard refuses and loader refuses"
nor "guard passes and loader accepts". A whole arm of the function was outside
both loops, and that arm was the one with the leak.

**State now (PR #217).** The guard reads the first document rather than the
stream, so the shape classified is the one the loader will deserialize. The
no-quoting test runs every command over two fixtures (single-document and
multi-document), and the missing arm has its own test,
`a_syntax_error_keeps_serdes_positional_diagnostic`, which asserts as an
*absence* that a deferred file's text cannot come back out.

**How to apply:** when reviewing this guard, probe shape *families* rather than
one fixture — single-doc scalar, multi-doc with a scalar first document, a
leading `---` (one document, must still load), tabs / unclosed flow (syntax
error), and JSON or k8s-Secret mappings (they used to load as a valid 0-rule
policy; #220 closed that in a *second* guard beside this one, so probe both —
see [[policy-load-error-echoes-file]]). More generally: if a test's name quantifies
over a property, check that its fixtures reach every branch of the function it
certifies, and treat a branch that fits none of the existing loops as a missing
test rather than as a branch that needs no test.

An absence assertion needs a "names the problem" companion per command, or an
earlier unrelated failure satisfies it — the same reason the gateway control in
`a_file_that_is_not_a_policy_is_named_rather_than_quoted` is now pinned to the
guard's own message instead of to a non-zero exit.

`#[cfg(unix)]` on a `vec![]` element compiles and strips cleanly, so gating one
command out of such a loop is sound; the gateway arm has to be gated because
`mgmt_token::random_bytes` bails on non-Unix before the policy is read. Note the
positional half of serde's syntax diagnostic is **not** universal: a reserved
indicator in column 1 yields a message with no line or column, which is why the
guard's doc claims a position only once the scanner is past the start.
