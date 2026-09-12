---
name: policy-load-error-echoes-file
description: "Policy::from_yaml on a file that is not a policy echoes its whole content into the error, because serde quotes the offending scalar; `honmoon policy validate` guards the shape first (#201), `run --policy` and `gateway --config` still do not"
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

**State after #201.** `honmoon policy validate` classifies the top-level shape itself
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
