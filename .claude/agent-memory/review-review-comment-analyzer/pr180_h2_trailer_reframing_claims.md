---
name: pr180-h2-trailer-reframing-claims
description: "hyper 1.10.1 citation pitfall in honmoon-proxy — `transfer_encoding_is_chunked`/`is_chunked` live in src/headers.rs, not src/proto/h1/headers.rs, which does not exist; verify a cited path before flagging or trusting it"
metadata:
  type: reference
---

`crates/honmoon-proxy/src/mitm.rs` and `body.rs` cite vendored hyper 1.10.1 line numbers heavily
(the trailer re-framing added in PR 180). Checked against
`~/.cargo/registry/src/index.crates.io-*/hyper-1.10.1/src/`:

- `proto/h1/encode.rs:212-215` (fixed-length `_` arm) and `:208-211` (`Kind::Chunked(None)`) — exact.
- `proto/h1/role.rs:1401-1418` (the `Trailer` allowlist) and `:1424-1427` (the guarded
  `Content-Length` removal) — exact.
- `proto/h2/mod.rs:43` (`strip_connection_headers`) — exact.
- **`src/headers.rs`** holds `transfer_encoding_is_chunked`, `is_chunked` and
  `content_length_parse_all`. There is **no** `src/proto/h1/headers.rs` in this crate; a doc
  comment citing that path was wrong and was corrected in PR 180.

**Why:** hyper has a crate-root `headers.rs` *and* a `proto/h1/` directory, so the wrong path is a
natural slip and reads as plausible to a reviewer who does not open it. The same name also exists
in both honmoon and hyper (`transfer_encoding_is_chunked`), which makes "mirrors hyper's X" claims
easy to attach to the wrong file.

**How to apply:** when a honmoon-proxy doc comment cites a vendored hyper path, resolve it on disk
before either trusting the claim or reporting it as wrong. Do not assume a `proto/h1/` prefix for
the header helpers.
