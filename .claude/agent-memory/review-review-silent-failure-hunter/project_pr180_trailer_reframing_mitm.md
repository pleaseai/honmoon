---
name: project-pr180-trailer-reframing-mitm
description: 'PR #180 (issue #136) framed_for_trailers in mitm.rs — the over-cap branches (retained_names returning Vec::new() when the frame is unread) log nothing at all when a trailer is present but cannot be preserved, unlike the signature-decline path which warns; the .to_str().ok() parses in declares_trailer/transfer_encoding_is_chunked deliberately mirror hyper''s own lenient parsing and are not real risk'
metadata:
  type: project
---

`framed_for_trailers` / `retained_names` in `crates/honmoon-proxy/src/mitm.rs` (added for
#136) declines to declare trailers over two paths: (1) a signed request where re-framing
would break a signature — this path correctly logs `tracing::warn!` with the broken headers
and trailer names (module convention); (2) the two over-cap branches in `inspect_body`
(`Some(len) => (body, None, len as i64, Vec::new())` and `Buffered::Overflow`), where the
frame was never read so `retained` is unconditionally `Vec::new()` — this path has **no log
at all**, even though a real trailer may exist and will silently fail to reach an h1
upstream. The doc comment on `retained_trailer_names` in `body.rs` acknowledges this as "the
residual tracked as issue 177," so it's a known, intentionally-scoped-out gap rather than an
oversight — but per [[feedback_framing_deliberate_skips]], a documented deliberate skip can
still lack a sub-guarantee (here: the module's own stated convention that "every bypass logs
a warn"). Worth re-checking whether issue 177 closes this with a log.

Separately: `declares_trailer` and `transfer_encoding_is_chunked` use `.to_str().ok()` /
`filter_map` to silently skip non-UTF-8 header values. This is a deliberate mirror of
hyper's own `headers::is_chunked` parsing (`hyper-1.10.1/src/headers.rs` — the doc comment
cited a `proto/h1/headers.rs` that does not exist and was corrected in PR 180), not
an independent gap — confirmed low risk, do not re-flag unless the mirrored hyper behavior
changes. `HeaderValue::from_str(&declared).expect(...)` in the same function is safe by
construction (`declared` is always a join of valid `HeaderName::as_str()` values).

Also noted: the new `framed_for_trailers` success log uses `tracing::debug!`, while the
module's comparable-weight mutation ("request body redacted") logs at `tracing::info!` —
an observability inconsistency for a mutation of forwarded request framing, not a silent
failure per se. **Declined in PR 180, do not re-raise without new argument:** the two are not
comparable weight. A redaction changes the bytes the client sent; the re-frame changes only how
the same bytes are delimited on one leg, and it fires on every pass-through request carrying a
trailer, so `info!` would be per-request noise. Every path that *loses* something still warns.

**How to apply:** if `inspect_body`'s over-cap branches or `retained_names` are touched
again (e.g. issue 177 work), check whether a log was added for the silent-trailer-loss case
described above.
