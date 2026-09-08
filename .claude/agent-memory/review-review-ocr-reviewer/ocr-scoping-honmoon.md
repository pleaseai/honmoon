---
name: ocr-scoping-honmoon
description: ocr Delegation Mode scoping/flags observed for the honmoon repo (review plugin config, base refs)
metadata:
  type: project
---

honmoon's `.please/config.yml` has no `review.ocr` flags section — `setup-env.sh
--print` reports `REVIEW_OCR_ENABLED=true` but no `REVIEW_OCR_DEFAULT_FLAGS`
value at all, so delegate invocations need no extra flags beyond the caller's
scope flags. `ocr` (from mise-installed node) is on PATH directly at
`~/.local/share/mise/installs/node/24/bin/ocr`, no `bunx` fallback needed on this
machine.

For a stacked-PR review where the caller passes `REVIEW_BASE_REF` (e.g.
`origin/amondnet/issue-85-endpoints-k8s-facts` for issue-86 built on issue-85),
use `ocr delegate preview --from "$REVIEW_BASE_REF" --to HEAD` even when the
working tree is clean — workspace-mode preview would come back empty in that
case, and the caller usually wants the committed range instead. Non-`.rs`
project docs (ADRs, README, roadmap, wiki) are excluded by ocr as
`unsupported_ext` — expected, not a warning.

See [[honmoon-postgres-sql-classification]] for what got reviewed under this
scope.
