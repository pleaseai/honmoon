//! Request-body buffering and `Content-Encoding` decoding for PII inspection.
//!
//! Split out of [`mitm`](crate::mitm) so the TLS-termination handler stays
//! focused on policy/gating. It produces bounded decoded bytes for inspection;
//! the caller decides whether findings are audit-only or enforced.
//!
//! Two invariants hold throughout:
//! - **Bounded memory**: no more than [`MAX_INSPECT_BODY`] bytes are ever
//!   buffered, and inflation reads at most one byte past that cap (only to
//!   detect overflow), so a large upload — or a decompression bomb — can't
//!   exhaust memory.
//! - **Untrusted headers**: `Content-Encoding` is client input. A body that
//!   fails to decode (mislabeled, corrupt, or an unsupported codec) falls back
//!   to scanning its raw bytes rather than skipping the scan — a plaintext body
//!   claiming to be compressed must not evade detection, and genuinely
//!   compressed bytes harmlessly fail the UTF-8 check downstream.

use std::borrow::Cow;
use std::io::Read;
use std::pin::Pin;
use std::task::Poll;

use http_body_util::BodyExt;
use http_body_util::combinators::BoxBody;
use hudsucker::Body;
use hudsucker::hyper::body::{Body as HttpBody, Bytes, Frame, SizeHint};

/// Max request-body bytes buffered in memory (and max inflated output) for PII
/// inspection. Bodies larger than this — whether declared by `Content-Length`,
/// discovered while reading an unknown-length body, or produced by
/// decompression — are left unscanned (streamed/truncated), so a large upload
/// can never exhaust memory.
pub(crate) const MAX_INSPECT_BODY: usize = 2 * 1024 * 1024;

/// Decode a buffered request body for inspection according to its
/// `Content-Encoding`. Returns the bytes to scan — borrowed for identity /
/// undecodable inputs, inflated for `gzip`/`deflate` — or `None` when the
/// inflated output exceeds [`MAX_INSPECT_BODY`]: a truncated prefix must not
/// feed a content-policy verdict, so an over-cap body is left unscanned,
/// exactly like an over-cap raw body.
///
/// Never returns "nothing to scan" for a *decodable* body: an undecodable one
/// (mislabeled, corrupt, or an unsupported codec such as `br`) falls back to
/// its raw bytes, because the header is untrusted and skipping would let a
/// plaintext body evade the scan by claiming to be compressed. Only the scan
/// sees this output — the original (still-encoded) body is what gets
/// forwarded.
pub(crate) fn decode_for_inspection<'a>(
    encoding: Option<&str>,
    raw: &'a [u8],
) -> Option<Cow<'a, [u8]>> {
    let token = encoding.map(|e| e.trim().to_ascii_lowercase());
    let attempt = match token.as_deref() {
        None | Some("") | Some("identity") => return Some(Cow::Borrowed(raw)),
        Some("gzip") | Some("x-gzip") => inflate_capped(flate2::read::MultiGzDecoder::new(raw)),
        // HTTP `deflate` is zlib-wrapped (RFC 9110 §8.4.1), but some senders
        // ship raw DEFLATE — try zlib first, then fall back to raw.
        Some("deflate") => inflate_capped(flate2::read::ZlibDecoder::new(raw))
            .or_else(|_| inflate_capped(flate2::read::DeflateDecoder::new(raw))),
        Some(other) => {
            // Unsupported codec (e.g. `br`, or a multi-token list): scan the raw
            // bytes rather than skip — see the untrusted-header invariant above.
            tracing::debug!(encoding = %other, "unsupported content-encoding; scanning raw bytes");
            return Some(Cow::Borrowed(raw));
        }
    };
    match attempt {
        Ok(Some(out)) => Some(Cow::Owned(out)),
        Ok(None) => {
            tracing::debug!(
                encoding = ?token,
                "decoded output exceeds inspection cap; leaving body unscanned"
            );
            None
        }
        Err(e) => {
            tracing::debug!(
                encoding = ?token,
                error = %e,
                "declared content-encoding failed to decode; scanning raw bytes"
            );
            Some(Cow::Borrowed(raw))
        }
    }
}

/// Inflate up to [`MAX_INSPECT_BODY`] bytes, reading one byte past the cap
/// only to detect overflow (decompression-bomb guard — memory stays bounded).
/// Returns `None` when the output overflows the cap, so the caller can leave
/// the body unscanned instead of judging a truncated prefix. Propagates the
/// decoder error so the caller can log the real cause (bad magic, checksum
/// mismatch, truncated stream).
fn inflate_capped<R: Read>(reader: R) -> std::io::Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    reader
        .take(MAX_INSPECT_BODY as u64 + 1)
        .read_to_end(&mut out)?;
    Ok((out.len() <= MAX_INSPECT_BODY).then_some(out))
}

/// The longest valid-UTF-8 prefix of `b`, tolerating only a *trailing*
/// incomplete sequence (a capped inflate can cut a multi-byte character in
/// half — that must not throw away the whole scan). Interior invalid bytes
/// still mean "not text": return `None` and skip the scan.
pub(crate) fn utf8_prefix(b: &[u8]) -> Option<&str> {
    match std::str::from_utf8(b) {
        Ok(s) => Some(s),
        Err(e) if e.error_len().is_none() => std::str::from_utf8(&b[..e.valid_up_to()]).ok(),
        Err(_) => None,
    }
}

/// Result of buffering an unknown-length body up to a cap.
pub(crate) enum Buffered {
    /// The body ended within the cap — fully buffered (trailers dropped, like
    /// the `Content-Length` buffered path).
    Complete(Bytes),
    /// The cap was hit: `prefix` holds exactly `limit` bytes, `rest` the
    /// remainder of the stream (including any unread tail of the frame that
    /// crossed the cap).
    Overflow { prefix: Bytes, rest: Body },
}

/// Read data frames from `body` until it ends or `limit` bytes have been
/// buffered. Never buffers more than `limit` bytes: a frame that crosses the
/// cap is split, with the unread tail pushed back into `rest` so forwarding
/// stays lossless.
pub(crate) async fn buffer_up_to(
    mut body: Body,
    limit: usize,
) -> Result<Buffered, hudsucker::Error> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Ok(mut data) = frame?.into_data() {
            if buf.len() + data.len() > limit {
                let take = limit - buf.len();
                buf.extend_from_slice(&data[..take]);
                let tail = data.split_off(take);
                return Ok(Buffered::Overflow {
                    prefix: Bytes::from(buf),
                    rest: prefixed_body(tail, body),
                });
            }
            buf.extend_from_slice(&data);
        }
    }
    Ok(Buffered::Complete(Bytes::from(buf)))
}

/// Re-assemble a body from an already-read prefix followed by the unread rest.
pub(crate) fn prefixed_body(prefix: Bytes, rest: Body) -> Body {
    Body::from(BoxBody::new(PrefixedBody {
        prefix: Some(prefix),
        rest,
    }))
}

/// An [`HttpBody`] that yields one prefix chunk, then delegates to `rest`.
struct PrefixedBody {
    prefix: Option<Bytes>,
    rest: Body,
}

impl HttpBody for PrefixedBody {
    type Data = Bytes;
    type Error = hudsucker::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(prefix) = self.prefix.take() {
            return Poll::Ready(Some(Ok(Frame::data(prefix))));
        }
        Pin::new(&mut self.rest).poll_frame(cx)
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = self.rest.size_hint();
        let prefix_len = self.prefix.as_ref().map(|p| p.len() as u64).unwrap_or(0);
        hint.set_lower(hint.lower() + prefix_len);
        if let Some(upper) = hint.upper() {
            hint.set_upper(upper + prefix_len);
        }
        hint
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).expect("gzip write");
        enc.finish().expect("gzip finish")
    }

    #[test]
    fn decode_identity_passes_bytes_through() {
        let raw = b"plain body";
        assert_eq!(
            decode_for_inspection(None, raw).expect("identity").as_ref(),
            &raw[..]
        );
        assert_eq!(
            decode_for_inspection(Some("identity"), raw)
                .expect("identity")
                .as_ref(),
            &raw[..]
        );
    }

    #[test]
    fn decode_gzip_inflates_body() {
        let compressed = gzip(b"rrn=670125-1230644");
        assert_eq!(
            decode_for_inspection(Some("gzip"), &compressed)
                .expect("gzip")
                .as_ref(),
            b"rrn=670125-1230644"
        );
        // Token normalization (case/whitespace) and the legacy alias.
        assert_eq!(
            decode_for_inspection(Some(" GZIP "), &compressed)
                .expect("gzip")
                .as_ref(),
            b"rrn=670125-1230644"
        );
        assert_eq!(
            decode_for_inspection(Some("x-gzip"), &compressed)
                .expect("gzip")
                .as_ref(),
            b"rrn=670125-1230644"
        );
    }

    #[test]
    fn decode_deflate_handles_zlib_and_raw() {
        use std::io::Write;

        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zlib.write_all(b"zlib-wrapped").unwrap();
        let zlib = zlib.finish().unwrap();
        assert_eq!(
            decode_for_inspection(Some("deflate"), &zlib)
                .expect("zlib")
                .as_ref(),
            &b"zlib-wrapped"[..]
        );

        let mut raw =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        raw.write_all(b"raw-deflate").unwrap();
        let raw = raw.finish().unwrap();
        assert_eq!(
            decode_for_inspection(Some("deflate"), &raw)
                .expect("deflate")
                .as_ref(),
            &b"raw-deflate"[..]
        );
    }

    #[test]
    fn unsupported_or_mislabeled_encoding_scans_raw_bytes() {
        // Unsupported codec (br) and multi-token lists we can't decode: the raw
        // bytes are scanned, not skipped — a plaintext body must not evade the
        // scan by wearing an encoding label we don't handle.
        let plain = b"plaintext rrn=670125-1230644";
        assert_eq!(
            decode_for_inspection(Some("br"), plain)
                .expect("raw")
                .as_ref(),
            &plain[..]
        );
        assert_eq!(
            decode_for_inspection(Some("gzip, br"), plain)
                .expect("raw")
                .as_ref(),
            &plain[..]
        );
        // Declared gzip/deflate that fails to decode also falls back to raw.
        assert_eq!(
            decode_for_inspection(Some("gzip"), plain)
                .expect("raw")
                .as_ref(),
            &plain[..]
        );
        assert_eq!(
            decode_for_inspection(Some("deflate"), plain)
                .expect("raw")
                .as_ref(),
            &plain[..]
        );
    }

    #[test]
    fn utf8_prefix_tolerates_only_trailing_truncation() {
        assert_eq!(utf8_prefix(b"plain ascii"), Some("plain ascii"));
        // "한" (3 bytes) cut after 2 bytes — the valid prefix is scanned.
        let mut cut = b"rrn ends with ".to_vec();
        cut.extend_from_slice(&"한".as_bytes()[..2]);
        assert_eq!(utf8_prefix(&cut), Some("rrn ends with "));
        // Interior invalid bytes mean "not text" — no scan.
        assert_eq!(utf8_prefix(b"bad \xFF\xFF middle"), None);
    }

    #[test]
    fn decompression_bomb_is_reported_as_overflow() {
        // Highly compressible payload far over the cap: a few KiB compressed,
        // 4× MAX_INSPECT_BODY inflated. Overflow must be reported (`None`) so
        // the caller leaves the body unscanned instead of judging a truncated
        // prefix; memory stays bounded (at most cap+1 bytes are inflated).
        let bomb = gzip(&vec![0u8; MAX_INSPECT_BODY * 4]);
        assert!(bomb.len() < MAX_INSPECT_BODY, "bomb should compress small");
        assert!(
            decode_for_inspection(Some("gzip"), &bomb).is_none(),
            "over-cap inflate must report overflow"
        );
    }

    #[test]
    fn decode_at_exactly_the_cap_is_not_overflow() {
        let at_cap = gzip(&vec![b'a'; MAX_INSPECT_BODY]);
        let decoded = decode_for_inspection(Some("gzip"), &at_cap).expect("at-cap decode");
        assert_eq!(decoded.len(), MAX_INSPECT_BODY);
    }

    #[tokio::test]
    async fn unknown_length_body_within_cap_is_fully_buffered() {
        let body = Body::from(b"small body".to_vec());
        match buffer_up_to(body, MAX_INSPECT_BODY).await.expect("read") {
            Buffered::Complete(bytes) => assert_eq!(&bytes[..], b"small body"),
            Buffered::Overflow { .. } => panic!("small body must not overflow"),
        }
    }

    #[tokio::test]
    async fn oversized_unknown_length_body_streams_through_intact() {
        let big = vec![b'a'; MAX_INSPECT_BODY + 10];
        let body = Body::from(big.clone());
        match buffer_up_to(body, MAX_INSPECT_BODY).await.expect("read") {
            Buffered::Complete(_) => panic!("oversized body must overflow"),
            Buffered::Overflow { prefix, rest } => {
                // The buffered prefix must be bounded at the cap even when a
                // single frame crosses it (the tail is pushed back into rest).
                assert_eq!(prefix.len(), MAX_INSPECT_BODY);
                // Nothing may be lost: prefix + rest must equal the original.
                let rest_bytes = prefixed_body(prefix, rest)
                    .collect()
                    .await
                    .expect("collect reassembled body")
                    .to_bytes();
                assert_eq!(&rest_bytes[..], &big[..]);
            }
        }
    }
}
