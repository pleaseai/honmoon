---
name: ocr-scoping-honmoon
description: ocr Delegation Mode setup specifics for the honmoon repo (no configured default flags, rule groups by extension)
metadata:
  type: project
---

In this repo, `.please/config.yml` has no `workflow.ocr` / delegate flags section, so
`REVIEW_OCR_DEFAULT_FLAGS` re-derives to empty via `setup-env.sh --print` — pass no extra
shared flags to `ocr delegate preview`/`rule` beyond caller-provided scope flags.

Rule resolution in this repo matches by extension, not by directory: `**/Cargo.toml` (Cargo
Manifest Hygiene / edition-MSRV / feature flags / release metadata) and `**/*.rs` (a broad
Rust rule set covering ownership/lifetimes, panics/unwraps, unsafe boundaries, concurrency,
async cancellation, collections/perf, API design, macros, and security-sensitive input
handling). `Cargo.lock` and `mise.lock` are excluded as `unsupported_ext` in preview — expect
them to show under the excluded-paths list, not the reviewable ledger.

**Why:** saves a re-derivation step and sets expectations for what preview/rule output looks
like on future honmoon PRs reviewed with ocr.
**How to apply:** when running ocr Delegation Mode in this repo, skip worrying about missing
default flags (it's expected), and don't be surprised when lockfiles are excluded.
