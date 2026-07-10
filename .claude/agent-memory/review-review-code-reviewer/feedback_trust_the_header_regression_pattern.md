---
name: feedback-trust-the-header-regression-pattern
description: When reviewing a diff that adds conditional decode/parse-then-scan logic keyed off a client-controlled header, check what happens on the "declared encoding but decode fails" path — don't dismiss it as equivalent to the honest-unsupported-encoding path
metadata:
  type: feedback
---

Pattern to watch for: code that branches scan/validation behavior on a client-supplied header (e.g. `Content-Encoding: gzip`) and, when the declared encoding fails to decode, silently skips the scan (returns `None`/no-op) instead of falling back to scanning the raw bytes.

**Why this matters**: my first pass on the honmoon `decode_for_inspection` diff (crates/honmoon-proxy/src/mitm.rs, PII-inspection-before-decompression feature, issue #12) initially framed the "corrupt gzip stream skips scan" case as low-severity/input-dependent, equivalent to the honest "unsupported encoding like `br`" case. The advisor caught that these are NOT equivalent:
- Honest unsupported encoding (`br`): bytes really are compressed, scanning raw is pointless — fine to skip.
- Declared-but-failed-to-decode (e.g. `Content-Encoding: gzip` on a plaintext body): this is a **regression** — before the decode step existed, raw bytes went straight to the scanner and plaintext PII was caught. After adding decode-before-scan, a client can trivially evade the scan by lying about `Content-Encoding` on an otherwise-plaintext body, since the decoder errors immediately (no gzip magic bytes) and the fallback is "skip scan" rather than "scan raw bytes anyway."
- This is trivially triggered (any plaintext body + a bogus encoding label, no crafting needed) and directly defeats the feature's stated purpose ("compressed bodies must not evade the scan").

**How to apply**: when a diff adds "if header X says format Y, decode as Y before doing check Z" logic, always ask: what does the code do when the header lies (declares Y but the bytes aren't actually Y)? If the answer is "skip check Z entirely," that's a real finding (important, not a footnote) — flag it and suggest falling back to running check Z on the raw/undecoded bytes when decode fails, since raw bytes that really are compressed will harmlessly fail whatever check Z is (e.g. `str::from_utf8`), while raw bytes that are actually plaintext will get caught.

See also [[project-agents-md-rules]].
