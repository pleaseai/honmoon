---
name: pr217-policy-scalar-leak
description: "A YAML shape guard must classify the file's first document, not the stream — honmoon's not_a_policy_document deferred on any parse error, and a multi-document file let serde quote a whole plain-scalar document anyway (found and closed in PR #217)"
metadata:
  type: project
---

`crates/honmoon-cli/src/main.rs` `not_a_policy_document` used to classify shape
with `serde_yaml::from_str::<serde_yaml::Value>(src)` and treat any parse error
as "defer to the loader" (`Err(_) => None`), on the premise that a YAML *syntax*
diagnostic names only the token it stopped on. That premise is false for a
**multi-document** file: `from_str::<Value>` refuses a multi-doc stream outright,
so the guard deferred — and `Policy::from_yaml` deserializes the *first* document
before it notices the second, so it reported
`invalid type: string "<whole first document, lines folded>"`.

Reproduced against the built binary for all three commands (`policy validate`,
`run --policy`, `gateway --config`) with a PEM block followed by a `---` line.
A multi-doc file whose first document is a *mapping* (k8s manifest, markdown
frontmatter) never leaked — serde reports "more than one document is not
supported", which carries no content.

**Closed in PR #217** (the same PR that lifted the guard into `load_policy`): the
guard now reads one document — `serde_yaml::Deserializer::from_str(src).next()`
then `Value::deserialize` — so what gets classified is the shape the loader will
try to deserialize. `serde` joined honmoon-cli's dependencies for that
(already a workspace dep of the other three crates).

**Why:** #202's whole point is that a non-policy file's contents must never be
quoted into stderr or a log, and a `---` line is ordinary in a `.env`, a
Kubernetes manifest or a helm values file — so this was not an exotic shape.

**How to apply:** do **not** re-report this as live; it is fixed, and
`every_shape_the_guard_refuses_is_one_the_loader_refuses_anyway` carries two
multi-document fixtures. Do keep the lesson: when a guard defers to a downstream
parser on error, the claim being made is about *that parser's* message, so probe
the parser rather than reading the guard. Two live sub-claims worth re-checking
if `serde_yaml` is ever replaced (TD-002): that the deferred text cannot come
back out (asserted by `a_syntax_error_keeps_serdes_positional_diagnostic`), and
that a stream whose first document is a mapping is still refused content-free.

An explicit leading `---` is **one** document, not a stream — a policy file may
open with it and must still load. That is pinned in the same unit test; a guard
that counted documents rather than reading the first would have broken it.

Out of scope for #217 and **since closed by #220** — do not report it as live.
`Policy` still does not deny unknown fields, so the *loader* still accepts any
mapping; `load_policy` no longer gives it one, refusing a mapping in which none
of `version`, `egress`, `endpoints`, `rules` appears. A `user:`/`password:` file
that printed "policy is valid (0 rules, 0 endpoints)" now exits non-zero on all
three commands. The refusal keeps two boundaries that a review here should check
rather than assume: an empty file is `null` and still loads, and one recognised
key admits unknown siblings, which is the forward-compatibility that ruled
`deny_unknown_fields` out. See the security reviewer's
[[policy-load-error-echoes-file]]. Related: [[framing-deliberate-skips]].
