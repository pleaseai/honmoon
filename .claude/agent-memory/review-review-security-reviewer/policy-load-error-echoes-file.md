---
name: policy-load-error-echoes-file
description: "Policy::from_yaml on a file that is not a policy echoes its whole content into the error, because serde quotes the offending scalar; closed for all three commands by the shared load_policy guard (#202), and the mapping-shaped residual (a secrets file or a JSON key loading as a valid 0-rule policy) is closed too, by load_policy refusing a mapping that declares no recognised policy key (#220) — do not report either as live"
metadata:
  type: project
---

`Policy::from_yaml` on a file that parses as a bare YAML scalar produces
`invalid type: string "<entire file content>", expected struct Policy`, and a CLI that prints
the error verbatim prints the file with it. Measured on the built binary before #201:

- a one-line token file → the token is printed;
- a PEM private key → the whole key is printed (YAML folds the lines into one plain scalar,
  so it all lands on one line).

**Why:** it is serde's `Unexpected::Str` Display, not honmoon code, so nothing in `main.rs` or
`honmoon-core` warns about it. The trigger is narrow and worth holding precisely — a document
whose **top level** is a scalar. A real policy is a mapping, and serde then quotes only the
offending field value; an empty file is `null`, which is a valid policy. So this is the
mistyped-path case, not the bad-policy case.

**State after #202 (PR #217) — the top-level-scalar leak is closed everywhere.** `not_a_policy_document`
moved out of `policy_validate` and into `load_policy` (`crates/honmoon-cli/src/main.rs`), which now
returns `(Policy, String)`; `gateway` lost its own inlined `read_to_string` + `from_yaml` and is the
only caller that keeps the source (it becomes `AppState.policy_yaml`). Verified on a rebuilt binary:
`policy validate`, `run --policy` and `gateway --config` all print
`… is not a policy document: its top level is plain text … Contents withheld` for a PEM, and a
`KEY=value` `.env` folds to a plain scalar so it is caught too. `load_policy` is the only non-test
`from_yaml` caller in `crates/*/src`, and `honmoonctl validate` is still a stub, so there is no second
read to drift.

**One shape survived the first version of that fix, and is also closed.** The guard
deferred on any `serde_yaml::from_str::<Value>` error, and a multi-document file is
such an error — while `Policy::from_yaml` deserializes the first document before it
notices the second, so a PEM block followed by a `---` line was still quoted whole from
all three commands. The guard now classifies the file's **first document** rather than
the stream. Probe that shape on any future change here; a `---` line is ordinary in a
`.env`, a Kubernetes manifest or a helm values file. See
[[policy-guard-multidoc-scalar-escapes]].

**The residual that survived #202 — closed by #220, do not re-report it as live.** Top-level `Policy`
still has NO `deny_unknown_fields` and every field still has a default, so *the loader* goes on
accepting any mapping; what changed is that `load_policy` no longer hands it one. It refuses a
mapping in which none of `version`, `egress`, `endpoints`, `rules` appears
(`mapping_names_no_policy_field`, `crates/honmoon-cli/src/main.rs`), so the k8s Secret manifest, the
`KEY: value` secrets file and the GCP service-account JSON key that all printed
`policy is valid (0 rules, 0 endpoints)` now exit non-zero on all three commands, and nothing reaches
`AppState.policy_yaml` to be served at `GET /api/policy`. Historical bound, worth keeping for scale:
egress default was `deny`, so the mis-target was fail-closed for traffic throughout, and the audience
for the source-serving was mgmt-token / dashboard-session holders (#173).

Two boundaries of that refusal are load-bearing and a review of this area should check them rather
than the refusal alone. An empty file is `null`, not a mapping, so it is still a valid policy. A
mapping with **at least one** recognised key is accepted whatever else it carries, so
forward-compatibility is intact and `deny_unknown_fields` is still the wrong fix — it was rejected
for #220 on exactly that ground, and the policy struct was deliberately left untouched so the change
stays off the `crates/AGENTS.md` **Ask first** list. An explicitly empty mapping (`{}`) is refused
and that is intended, not a bug.

**The residual of the residual, measured on the #220 build (do not re-derive).** The admission
ticket is the *name* of one of `version`, `egress`, `endpoints`, `rules`, and `version` is a generic
name other config formats use. Measured with the built binary: `version: 3` + `services:` with a
`POSTGRES_PASSWORD:` (an ordinary docker-compose file) still answers
`policy is valid (0 rules, 0 endpoints)` and, under `gateway --config`, its whole text still reaches
`AppState.policy_yaml` → `GET /api/policy`. `version: "3.8"` (quoted) does not — serde fails the
`u32` and quotes only `"3.8"`. Also measured and *not* gaps: a k8s Secret, a `KEY: value` file, a
service-account JSON, `{}`, a tagged mapping, a complex (non-string) key, `Version:`/`Rules:` case
variants, a `%YAML` directive, a BOM'd file and a merge-key-only document are all refused with no
content in the message; a `---\n---\n<PEM>` (empty first document) does not leak either — the
loader stops at "more than one document". Multi-document files never load at all, though which guard *answers* for one moved in #239: a stream whose first document is a secrets mapping is now refused by the recognised-key rule for the path, not by the loader for being a stream.

The compose case is **tracked in #240**, with the reasoning for leaving it open — dropping `version` from the admission set would refuse a file containing only `version: 1`, a policy the gateway starts on. Do not re-file it, and do not report it as an oversight in #239: it is pinned there by `version_alone_admits_a_file_no_operator_wrote_as_a_policy` and stated in `wiki/getting-started/policy-authoring.md`.

**State after #201 (historical).** `honmoon policy validate` classifies the top-level shape itself
(`not_a_policy_document` in `crates/honmoon-cli/src/main.rs`) and refuses plain text, a list or
a single value by name, without quoting. It refuses nothing the loader would have accepted, so
no verdict moved. **`honmoon run --policy` and `honmoon gateway --config` still propagate the
serde message** — they are operator-interactive rather than CI-facing, which is why #201 left
them, and a mapping carrying a long string value still reaches serde's quoting on every path.

**How to apply:** when reviewing anything that widens where a policy path comes from, or adds
another `from_yaml` caller, ask whether that error reaches a log the operator did not choose.
Do not re-report `policy validate` for this — check the guard is still there instead. See
[[policy-yaml-trust-boundary]]: the YAML body is trusted author input, so the exposure is the
*path*, never the content.

Secondary, same command: `policy validate` defaults tracing to `warn`, so
`warn_undefined_endpoints` / `warn_shadowed_rules` print rule and endpoint names on an exit-0
run. Deliberate — a warning is the diagnosis — and #201's `--help` and wiki both say so rather
than claiming a clean run prints only counts.
