---
name: pr239-mapping-names-no-policy-field-claims
description: "PR #239 (issue #220) doc-comment audit of load_policy's second guard — which claims were mechanically checkable and held, and the one that did not: a clause naming which guard refuses a multi-document stream stayed false through a clean audit and was caught only by running the case"
metadata:
  type: project
---

PR #239 adds `mapping_names_no_policy_field` beside the pre-existing `not_a_policy_document` in
`crates/honmoon-cli/src/main.rs`'s `load_policy`. A full claim-by-claim audit of the new prose
came back clean, and **a real inaccuracy was still there.** Both halves are the point of this
note; read the second before trusting the first.

**What the audit checked and confirmed** (symbols, not line numbers — the ranges cited in the
wiki moved twice inside this same PR, so re-resolve rather than trusting any number written here):

- `not_a_policy_document`'s "no verdict moves" claim is scoped to that function and says so
  ("That is a claim about this function"), and the new prose above `load_policy` distinguishes
  the two guards outright — the first rewords, the second moves a verdict on purpose. So the
  older claim does not read as a property of the whole read. Not a defect, despite being the
  shape of change that usually produces one.
- `Policy::from_yaml(src: &str)` takes no path, supporting "the library has no path to name".
- `honmoon-mgmt`'s `get_policy` clones an already-built `Policy` and never parses YAML, so
  "a `Policy` built in a test, a bench or `honmoon-mgmt` is not a file anybody mistyped" holds.
- `crates/AGENTS.md`'s Ask-first list names the policy struct shape; this PR does not touch it.
- `Policy`'s fields are exactly `version, egress, endpoints, rules`, each `#[serde(default)]`,
  no `deny_unknown_fields` — matching `POLICY_FIELDS` and every "any mapping deserializes" claim.
- `policy_fields_are_exactly_the_ones_policy_declares` exists and asserts membership *and* order.
- `names_no_policy_field` matches keys with `Value::as_str`, and that reads a **tagged key**
  (`!custom version: 1`) through its tag: `serde_yaml` 0.9's `as_str` calls `untag_ref` first.
  Two review bots (cubic, codex) reported the opposite on the same line in the same minute; it
  was settled by running it, and is pinned by `a_tagged_key_is_read_through_its_tag`. Do not
  re-raise "unwrap `Value::Tagged` before matching `POLICY_FIELDS`" without re-running that test.

**What it missed, and why.** `not_a_policy_document`'s doc said a stream whose first document is
a mapping "still passes through, and the loader refuses it for being a stream". Every word of
that was true before this PR and the first clause is still true — but the second stopped being
true for the common case, because the new guard now answers first whenever that mapping declares
no policy field, which is exactly what a Kubernetes manifest carrying a `---` line is. The audit
read the sentence against the function it annotates, where it is correct, rather than against the
*sequence* the function now sits in. It was found by running the case, not by reading.

**How to apply.** A clause naming *which* component refuses something is a claim about call
order, so check it against the caller, not only against the function the comment sits on — adding
a second guard in front of an existing one silently re-points every such clause in both. And
prefer probing to re-reading when a claim is cheap to execute: the same PR also settled
merge-key, alias, nested-key and stream behaviour by running them, which turned three suspected
gaps into two recorded non-gaps and one real correction. Contrast [[pr217-load-policy-consumer-claim]]
and [[pr201-policy-validate-claims]], the two earlier rounds on this same function, where the
defect *was* reachable by reading (a named consumer that was wrong, a guarantee stated too
generally).
