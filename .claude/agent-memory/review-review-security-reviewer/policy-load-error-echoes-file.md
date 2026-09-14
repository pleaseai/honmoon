---
name: policy-load-error-echoes-file
description: "Policy::from_yaml on a file that is not a policy echoes its whole content into the error, because serde quotes the offending scalar; closed for all three commands by the shared load_policy guard (#202), with the mapping-shaped residual (a colon-style secrets file or a JSON key loads as a valid 0-rule policy and is served at GET /api/policy) still open"
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

**The residual worth remembering (pre-existing, not introduced by #202):** top-level `Policy` has NO
`deny_unknown_fields` and every field has a default, so any *mapping*-shaped file loads as a valid
0-rule policy. Measured: a k8s Secret manifest, a `KEY: value` secrets file and a GCP
service-account JSON key (JSON is YAML) all print `policy is valid (0 rules, 0 endpoints)` and exit 0.
Nothing is quoted to stderr, but under `gateway` the file's full text becomes `AppState.policy_yaml`
and is served as the `yaml` field of authenticated `GET /api/policy`. Egress default is `deny`, so the
mis-target is fail-closed for traffic; the exposure is the source-serving, audience = mgmt-token /
dashboard-session holders.

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
