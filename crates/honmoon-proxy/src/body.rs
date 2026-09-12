//! Request-body buffering, `Content-Encoding` decoding for PII inspection and
//! redaction, and streaming response detokenization.
//!
//! Split out of [`mitm`](crate::mitm) so the TLS-termination handler stays
//! focused on policy/gating. Request helpers produce bounded decoded bytes for
//! inspection or rewriting; the response adapter restores known placeholders
//! without buffering the upstream stream.
//!
//! Three invariants hold throughout:
//! - **Bounded memory**: no more than [`MAX_INSPECT_BODY`] bytes are ever
//!   buffered, and inflation reads at most one byte past that cap (only to
//!   detect overflow), so a large upload — or a decompression bomb — can't
//!   exhaust memory.
//! - **Untrusted headers**: `Content-Encoding` is client input. A body that
//!   fails to decode (mislabeled, corrupt, or an unsupported codec) falls back
//!   to scanning its raw bytes rather than skipping the scan — a plaintext body
//!   claiming to be compressed must not evade detection, and genuinely
//!   compressed bytes harmlessly fail the UTF-8 check downstream.
//! - **Bodies only**: the helpers here produce *body* bytes for inspection.
//!   Trailers are carried through this module to be replayed on the
//!   pass-through path, but carrying is not scanning — trailer and header
//!   values are never scanned for PII or secrets, never passed to a detector
//!   and never redacted anywhere in the pipeline. (Headers *are* read, for
//!   framing, decoding and signature metadata — that is metadata handling, not
//!   detection.) Whether a
//!   carried trailer survives is a separate, conditional matter, and there are
//!   two conditions: a wire redaction rewrite replaces the body with `Full`,
//!   which has no trailer frame, so the client's trailers are dropped there
//!   (see `mitm::HonmoonHandler::forwarded_request`); and a trailer whose
//!   *name* a trailer section must not carry is dropped by
//!   [`trailer_filtered_body`] on every **request**-forwarding path. Neither
//!   decision reads a value. Response trailers are not filtered by name at all
//!   — [`detokenizing_body`] forwards the upstream's trailer frame to the
//!   client unmodified — because the hazard #134 is about is a *client*
//!   laundering a framing token into honmoon's upstream leg. See
//!   `.please/docs/decisions/0009-body-only-inspection-contract.md`.

use std::borrow::Cow;
use std::io::Read;
use std::pin::Pin;
use std::task::Poll;

use honmoon_core::{Mapping, StreamingDetokenizer};
use http_body_util::BodyExt;
use http_body_util::combinators::BoxBody;
use hudsucker::Body;
use hudsucker::hyper::HeaderMap;
use hudsucker::hyper::body::{Body as HttpBody, Bytes, Frame, SizeHint};
use hudsucker::hyper::header::{
    AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE,
    CONTENT_TYPE, COOKIE, HOST, HeaderName, MAX_FORWARDS, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION,
    SET_COOKIE, TE, TRAILER, TRANSFER_ENCODING, UPGRADE, WWW_AUTHENTICATE,
};

/// Max request-body bytes buffered in memory (and max inflated output) for PII
/// inspection. Bodies larger than this — whether declared by `Content-Length`,
/// discovered while reading an unknown-length body, or produced by
/// decompression — are left unscanned (streamed/truncated), so a large upload
/// can never exhaust memory.
pub(crate) const MAX_INSPECT_BODY: usize = 2 * 1024 * 1024;

/// Result of strictly decoding a buffered request body.
pub(crate) enum StrictDecode<'a> {
    Decoded(Cow<'a, [u8]>),
    Overflow,
    Unavailable,
}

/// Strictly decode a buffered request body once for both inspection and wire
/// redaction. Unsupported or malformed encodings are distinguished from
/// over-cap inflation because inspection scans the former as raw bytes while an
/// overflow must stay uninspected.
pub(crate) fn decode_strict<'a>(encoding: Option<&str>, raw: &'a [u8]) -> StrictDecode<'a> {
    let token = encoding.map(|e| e.trim().to_ascii_lowercase());
    let attempt = match token.as_deref() {
        None | Some("") | Some("identity") => {
            return StrictDecode::Decoded(Cow::Borrowed(raw));
        }
        Some("gzip") | Some("x-gzip") => inflate_capped(flate2::read::MultiGzDecoder::new(raw)),
        Some("deflate") => inflate_capped(flate2::read::ZlibDecoder::new(raw))
            .or_else(|_| inflate_capped(flate2::read::DeflateDecoder::new(raw))),
        Some(_) => return StrictDecode::Unavailable,
    };
    match attempt {
        Ok(Some(out)) => StrictDecode::Decoded(Cow::Owned(out)),
        Ok(None) => StrictDecode::Overflow,
        Err(_) => StrictDecode::Unavailable,
    }
}

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
#[cfg(test)]
pub(crate) fn decode_for_inspection<'a>(
    encoding: Option<&str>,
    raw: &'a [u8],
) -> Option<Cow<'a, [u8]>> {
    match decode_strict(encoding, raw) {
        StrictDecode::Decoded(decoded) => Some(decoded),
        StrictDecode::Overflow => {
            tracing::debug!(
                encoding = ?encoding,
                "decoded output exceeds inspection cap; leaving body unscanned"
            );
            None
        }
        StrictDecode::Unavailable => {
            tracing::debug!(
                encoding = ?encoding,
                "content-encoding unavailable for strict decode; scanning raw bytes"
            );
            Some(Cow::Borrowed(raw))
        }
    }
}

/// Strictly decode a buffered request body for wire redaction.
///
/// Unlike [`decode_for_inspection`], this never falls back to raw bytes for an
/// unsupported or malformed declared encoding: rewriting those bytes as identity
/// text would corrupt the request. `None` is the documented fail-open signal.
#[cfg(test)]
pub(crate) fn decode_for_redaction<'a>(
    encoding: Option<&str>,
    raw: &'a [u8],
) -> Option<Cow<'a, [u8]>> {
    match decode_strict(encoding, raw) {
        StrictDecode::Decoded(decoded) => Some(decoded),
        StrictDecode::Overflow | StrictDecode::Unavailable => None,
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
    /// The body ended within the cap — fully buffered, together with any
    /// trailers the client sent after the last data frame.
    Complete {
        bytes: Bytes,
        trailers: Option<HeaderMap>,
    },
    /// The cap was hit: `prefix` holds exactly `limit` bytes, `rest` the
    /// remainder of the stream (including any unread tail of the frame that
    /// crossed the cap).
    Overflow { prefix: Bytes, rest: Body },
}

/// Read data frames from `body` until it ends or `limit` bytes have been
/// buffered. Never buffers more than `limit` bytes: a frame that crosses the
/// cap is split, with the unread tail pushed back into `rest` so forwarding
/// stays lossless.
///
/// Trailer frames are kept rather than skipped: they are part of the request
/// the client sent, and a signature can cover a `Content-Digest` carried there.
/// The overflow path needs no such care — trailers arrive after the last data
/// frame, so they are still unread in `rest`.
///
/// Kept for *forwarding*, not for inspection: the returned `trailers` are
/// handed back to be replayed upstream and never scanned. Replayed on the
/// pass-through path only — a wire-redaction rewrite replaces the body with
/// `Full`, which carries no trailer frame, so these are dropped there
/// (deliberately; see `forwarded_request`) — and then only for the names
/// [`trailer_filtered_body`] does not refuse. Note the asymmetry that
/// makes widening the scan here unsound — this is one of only two places a
/// trailer materializes at all (the other is `inspect_body`'s
/// `Content-Length <= MAX_INSPECT_BODY` branch, which collects them separately),
/// so a scan added here would cover the unknown-length within-cap path alone and
/// silently miss both over-cap ones, whose trailers stay unread in `rest`
/// (ADR-0009).
pub(crate) async fn buffer_up_to(
    mut body: Body,
    limit: usize,
) -> Result<Buffered, hudsucker::Error> {
    let mut buf: Vec<u8> = Vec::new();
    let mut trailers: Option<HeaderMap> = None;
    while let Some(frame) = body.frame().await {
        match frame?.into_data() {
            Ok(mut data) => {
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
            Err(frame) => {
                if let Ok(more) = frame.into_trailers() {
                    match &mut trailers {
                        Some(seen) => seen.extend(more),
                        None => trailers = Some(more),
                    }
                }
            }
        }
    }
    Ok(Buffered::Complete {
        bytes: Bytes::from(buf),
        trailers,
    })
}

/// Re-assemble a fully buffered body: the buffered bytes, then the trailers the
/// client sent after them.
///
/// [`Full`](http_body_util::Full) cannot carry trailers, so rebuilding with it
/// silently drops the client's trailer frame. That breaks the promise
/// `--signed-body forward` makes — an RFC 9421 or draft-cavage signature may
/// cover a `Content-Digest` the client sent as a trailer, and a request
/// forwarded without it earns the upstream signature rejection the mode exists
/// to avoid. `Content-Digest` is not among [`FORBIDDEN_TRAILER_FIELDS`], so the
/// name filter downstream of this does not take it back.
pub(crate) fn buffered_body(bytes: Bytes, trailers: Option<HeaderMap>) -> Body {
    Body::from(BoxBody::new(BufferedBody {
        // An empty `Bytes` yields no data frame, matching `Full`.
        data: (!bytes.is_empty()).then_some(bytes),
        trailers,
    }))
}

/// Field names honmoon refuses to forward in a request trailer section.
///
/// RFC 9110 §6.5.1 states this as *categories*, not as a list: a sender must
/// not put a field in a trailer section when it describes "message framing,
/// routing, authentication, request modifiers, response controls, or content
/// format". The names below resolve the subset of those categories that can
/// change **how a recipient frames, routes, or authenticates the request** —
/// which is the hazard the same section warns about, and which RFC 7230 §4.1.2
/// (its obsoleted predecessor, and the source of hyper's own enumeration)
/// stated outright: a recipient must ignore a forbidden trailer field, "since
/// processing them as if they were present in the header section might bypass
/// external security filters."
///
/// - **Framing** — `Transfer-Encoding`, `Content-Length`. The CWE-444 case.
/// - **Routing** — `Host`. (`:authority` needs no entry: `:` is not a valid
///   `HeaderName` token, so neither hyper's trailer decoder nor `h2` can produce
///   one.)
/// - **Authentication** (RFC 9110 §11 and RFC 6265, both named by §6.5.1) —
///   `Authorization`, `Proxy-Authorization`, `WWW-Authenticate`,
///   `Proxy-Authenticate`, `Cookie`, `Set-Cookie`. The whole category, not the
///   two names hyper happens to list: `Cookie` is the request-direction twin of
///   `Set-Cookie`, and `Proxy-Authorization` of `Authorization`.
/// - **Content processing** — `Content-Encoding`, `Content-Type`,
///   `Content-Range`, `Trailer`.
/// - **Request modifiers** — `Cache-Control`, `Max-Forwards`, `TE`, and only
///   those. See below.
/// - **RFC 9113 §8.2.2 connection-specific fields**, which an HTTP/2 message may
///   not carry at all — `Connection`, `Keep-Alive`, `Proxy-Connection`,
///   `Upgrade` (`Transfer-Encoding` and `TE` are already above), plus whatever
///   names a request's `Connection` header nominates, which
///   [`connection_nominated`] resolves per request. hyper strips exactly this
///   set from request *headers* — `strip_connection_headers`
///   (`proto/h2/mod.rs:43`, called from `proto/h2/client.rs:709`) — and never
///   from a trailer frame, which is the gap #134 is about.
///
/// **Deliberately not filtered**, so the next reader does not have to re-derive
/// it: the rest of §6.5.1's "request modifiers" and "response controls"
/// categories — the conditionals (`If-Match`, `If-None-Match`,
/// `If-Modified-Since`, `If-Unmodified-Since`, `If-Range`), `Range`, `Expect`,
/// `Pragma`, and the `Accept*` content-selection family. A trailer carrying one
/// of those is malformed, but it changes what the recipient *returns*, not how
/// it frames, routes or authorizes the request, so dropping it buys no security
/// and widens honmoon's interference with the byte fidelity `--signed-body
/// forward` promises (ADR-0006). This list is a security filter, not a
/// conformance enforcer. `Cache-Control`, `Max-Forwards` and `TE` are the
/// exception only because hyper's h1 encoder already refuses them
/// (`is_valid_trailer_field`, `hyper-1.10.1/src/proto/h1/encode.rs:264`) — they
/// stay so the two upstream legs refuse the same names.
///
/// The result is a strict superset of hyper's h1 enumeration, so nothing an h1
/// upstream would have rejected now survives an h2 one.
static FORBIDDEN_TRAILER_FIELDS: [HeaderName; 20] = [
    AUTHORIZATION,
    CACHE_CONTROL,
    CONNECTION,
    CONTENT_ENCODING,
    CONTENT_LENGTH,
    CONTENT_RANGE,
    CONTENT_TYPE,
    COOKIE,
    HOST,
    HeaderName::from_static("keep-alive"),
    MAX_FORWARDS,
    PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION,
    HeaderName::from_static("proxy-connection"),
    SET_COOKIE,
    TE,
    TRAILER,
    TRANSFER_ENCODING,
    UPGRADE,
    WWW_AUTHENTICATE,
];

/// The field names a request's `Connection` header nominates as
/// connection-specific, which RFC 9110 §7.6.1 forbids an intermediary from
/// forwarding and RFC 9113 §8.2.2 forbids an HTTP/2 message from carrying.
///
/// Parsed exactly as hyper parses it for request headers (`strip_connection_headers`,
/// `proto/h2/mod.rs:43`) — comma-separated, trimmed, one `HeaderName` each. The
/// asymmetry this closes is hyper's: it applies the nomination to the header
/// section and not to the trailer section, so `Connection: X-Foo` plus an
/// `X-Foo` trailer forwarded a field the client itself marked hop-by-hop.
///
/// Returns an empty `Vec` — which allocates nothing — for the overwhelmingly
/// common request that sends no `Connection` header, or none naming a field.
fn connection_nominated(headers: &HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect()
}

/// The field names a trailer section would still carry after
/// [`trailer_filtered_body`] has run over it.
///
/// The read-only counterpart of [`strip_forbidden_trailers`], for the one thing
/// the streaming filter cannot answer in time: hyper's h1 encoder emits only the
/// trailer fields a request's `Trailer` **header** names
/// (`hyper-1.10.1/src/proto/h1/role.rs:1401-1418`), and that header has to be
/// written while the header section is still in hand — long before the filter
/// sees the frame. `mitm` declares exactly these names, so nothing is declared
/// that the filter will then drop (#136).
///
/// Both directions read [`FORBIDDEN_TRAILER_FIELDS`] and [`connection_nominated`],
/// so the rule has one definition; `retained_names_match_the_streaming_filter`
/// pins the two against each other.
///
/// Only the two branches of `inspect_body` that buffer a body ever hold a
/// trailer `HeaderMap` to ask about. On the two over-cap ones the frame is still
/// unread when the header section is written, so no declaration can be
/// synthesized for it — see the module note on [`buffer_up_to`].
pub(crate) fn retained_trailer_names(trailers: &HeaderMap, headers: &HeaderMap) -> Vec<HeaderName> {
    let nominated = connection_nominated(headers);
    trailers
        .keys()
        .filter(|name| !FORBIDDEN_TRAILER_FIELDS.contains(name) && !nominated.contains(name))
        .cloned()
        .collect()
}

/// Remove every [`FORBIDDEN_TRAILER_FIELDS`] entry, and every `nominated` name,
/// from `trailers`, returning the names dropped.
///
/// `HeaderMap::remove` takes the whole entry — it follows the extra-value links
/// before removing (`http-1.5.0/src/header/map.rs`) — so a name sent several
/// times is removed in full rather than leaving later values behind. A
/// `nominated` name that is also a static entry removes nothing the second time,
/// so it is named once in the return.
fn strip_forbidden_trailers<'a>(
    trailers: &mut HeaderMap,
    nominated: &'a [HeaderName],
) -> Vec<&'a str> {
    FORBIDDEN_TRAILER_FIELDS
        .iter()
        .chain(nominated.iter())
        .filter(|name| trailers.remove(*name).is_some())
        .map(HeaderName::as_str)
        .collect()
}

/// Filter [`FORBIDDEN_TRAILER_FIELDS`] out of whatever trailer frame the client
/// sent, wherever that frame comes from.
///
/// This is a *streaming* adapter rather than a rewrite of the buffered
/// `HeaderMap` deliberately. Only two of `inspect_body`'s four branches ever
/// materialize trailers; on the two over-cap ones the body is forwarded
/// untouched and its trailer frame is still unread, so a filter applied to the
/// buffered `HeaderMap` would cover half the paths and be silently absent on the
/// rest — the asymmetry #134 is about in the first place. Wrapping the forwarded
/// body covers all four with one rule.
///
/// The filter runs regardless of which protocol the upstream leg negotiates,
/// because ALPN has not happened yet when the request is built, and it is not
/// redundant on either. Hyper's h1 encoder refuses only its own 12-name
/// enumeration (`is_valid_trailer_field`), which contains neither the
/// connection-specific names of RFC 9113 §8.2.2 nor the rest of the
/// authentication category — `is_valid_trailer_field(CONNECTION)` answers
/// *true*. So on an h1 upstream this is what removes those, and on an h2
/// upstream it is what removes anything at all.
///
/// A frame left empty by the filter is dropped rather than forwarded: an empty
/// trailer section carries nothing, hyper's h1 encoder writes nothing for it,
/// and h2 ends the stream with an empty EOS `DATA` frame instead.
///
/// `headers` supplies the request's `Connection` nominations (see
/// [`connection_nominated`]); `host` only labels the `warn` a drop emits, so an
/// operator can tell which destination a stripped trailer was bound for.
pub(crate) fn trailer_filtered_body(body: Body, headers: &HeaderMap, host: &str) -> Body {
    Body::from(BoxBody::new(TrailerFilteredBody {
        inner: body,
        nominated: connection_nominated(headers),
        host: host.to_owned(),
    }))
}

/// An [`HttpBody`] that passes data frames through and filters trailer frames.
struct TrailerFilteredBody {
    inner: Body,
    /// Resolved once per request, because the `Connection` header is gone from
    /// `parts` long before the trailer frame arrives.
    nominated: Vec<HeaderName>,
    host: String,
}

impl HttpBody for TrailerFilteredBody {
    type Data = Bytes;
    type Error = hudsucker::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        loop {
            let frame = match std::task::ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                Some(Ok(frame)) => frame,
                other => return Poll::Ready(other),
            };
            let mut trailers = match frame.into_trailers() {
                Ok(trailers) => trailers,
                Err(data) => return Poll::Ready(Some(Ok(data))),
            };
            let dropped = strip_forbidden_trailers(&mut trailers, &this.nominated);
            if !dropped.is_empty() {
                tracing::warn!(
                    domain = %this.host,
                    fields = %dropped.join(", "),
                    "dropped trailer fields a trailer section must not carry from forwarded request"
                );
            }
            if trailers.is_empty() {
                continue;
            }
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    /// Data bytes only, so filtering trailers never changes it.
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Re-assemble a body from an already-read prefix followed by the unread rest.
pub(crate) fn prefixed_body(prefix: Bytes, rest: Body) -> Body {
    Body::from(BoxBody::new(PrefixedBody {
        prefix: Some(prefix),
        rest,
    }))
}

pub(crate) fn detokenizing_body(body: Body, mapping: Mapping) -> Body {
    Body::from(BoxBody::new(DetokenizingBody {
        inner: body,
        detokenizer: Some(StreamingDetokenizer::owned(mapping)),
        carry: Vec::new(),
        pending: None,
        passthrough: false,
        finished: false,
    }))
}

/// A streaming response body that restores known placeholders without buffering
/// the response. The detokenizer may withhold at most
/// `MAX_PLACEHOLDER_LEN - 1` bytes between frames; for SSE those bytes flush
/// with the next frame or at stream end.
///
/// UTF-8 code points split across frames use a carry of at most three bytes. An
/// interior invalid sequence permanently switches to byte-for-byte pass-through:
/// placeholders are ASCII, but splicing secrets into a binary stream is unsafe.
struct DetokenizingBody {
    inner: Body,
    detokenizer: Option<StreamingDetokenizer<'static>>,
    carry: Vec<u8>,
    pending: Option<Frame<Bytes>>,
    passthrough: bool,
    finished: bool,
}

impl DetokenizingBody {
    fn transform_data(&mut self, data: Bytes) -> Bytes {
        if self.passthrough {
            return data;
        }

        // Common case: no carry from the prior frame — borrow `data` directly
        // instead of allocating a combined buffer on every frame.
        let mut combined_storage;
        let combined: &[u8] = if self.carry.is_empty() {
            &data
        } else {
            combined_storage = std::mem::take(&mut self.carry);
            combined_storage.extend_from_slice(&data);
            &combined_storage
        };
        match std::str::from_utf8(combined) {
            Ok(text) => Bytes::from(
                self.detokenizer
                    .as_mut()
                    .expect("detokenizer present before pass-through")
                    .push(text),
            ),
            Err(error) if error.error_len().is_none() => {
                let valid_up_to = error.valid_up_to();
                let output = self
                    .detokenizer
                    .as_mut()
                    .expect("detokenizer present before pass-through")
                    .push(
                        std::str::from_utf8(&combined[..valid_up_to])
                            .expect("UTF-8 valid_up_to is valid text"),
                    );
                self.carry.extend_from_slice(&combined[valid_up_to..]);
                debug_assert!(self.carry.len() <= 3);
                Bytes::from(output)
            }
            Err(_) => {
                tracing::warn!(
                    "response detokenization abandoned because response body is not valid UTF-8; forwarding remaining bytes verbatim"
                );
                // Flush undecided placeholder text and the bytes carried from the
                // prior frame verbatim before preserving this binary stream.
                let mut output = self
                    .detokenizer
                    .take()
                    .expect("detokenizer present before pass-through")
                    .finish()
                    .into_bytes();
                output.extend_from_slice(combined);
                self.passthrough = true;
                Bytes::from(output)
            }
        }
    }

    fn finish_bytes(&mut self) -> Option<Bytes> {
        if self.finished {
            return None;
        }
        self.finished = true;
        if self.passthrough {
            return None;
        }
        let mut output = self
            .detokenizer
            .take()
            .expect("detokenizer present before finish")
            .finish()
            .into_bytes();
        output.append(&mut self.carry);
        (!output.is_empty()).then(|| Bytes::from(output))
    }
}

impl HttpBody for DetokenizingBody {
    type Data = Bytes;
    type Error = hudsucker::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(frame) = self.pending.take() {
            return Poll::Ready(Some(Ok(frame)));
        }
        if self.finished {
            return Poll::Ready(None);
        }

        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => Poll::Ready(Some(Ok(Frame::data(self.transform_data(data))))),
                Err(frame) => match self.finish_bytes() {
                    Some(bytes) => {
                        self.pending = Some(frame);
                        Poll::Ready(Some(Ok(Frame::data(bytes))))
                    }
                    None => Poll::Ready(Some(Ok(frame))),
                },
            },
            Poll::Ready(None) => match self.finish_bytes() {
                Some(bytes) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
                None => Poll::Ready(None),
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished && self.pending.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

/// An [`HttpBody`] that yields one data frame, then the buffered trailers.
struct BufferedBody {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl HttpBody for BufferedBody {
    type Data = Bytes;
    type Error = hudsucker::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(data) = self.data.take() {
            return Poll::Ready(Some(Ok(Frame::data(data))));
        }
        Poll::Ready(self.trailers.take().map(|t| Ok(Frame::trailers(t))))
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none() && self.trailers.is_none()
    }

    /// Exact, and counting data bytes only — trailers are not body length.
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.data.as_ref().map_or(0, |data| data.len() as u64))
    }
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
    use std::collections::VecDeque;
    use std::task::{Context, Poll};

    use super::*;
    use hudsucker::hyper::HeaderMap;

    struct ScriptedBody {
        frames: VecDeque<Result<Frame<Bytes>, hudsucker::Error>>,
    }

    impl HttpBody for ScriptedBody {
        type Data = Bytes;
        type Error = hudsucker::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(self.frames.pop_front())
        }
    }

    fn scripted_body(frames: Vec<Result<Frame<Bytes>, hudsucker::Error>>) -> Body {
        Body::from(BoxBody::new(ScriptedBody {
            frames: frames.into(),
        }))
    }

    fn detokenizer_with_inner(mapping: Mapping, inner: Body) -> DetokenizingBody {
        DetokenizingBody {
            inner,
            detokenizer: Some(StreamingDetokenizer::owned(mapping)),
            carry: Vec::new(),
            pending: None,
            passthrough: false,
            finished: false,
        }
    }

    fn detokenizer(mapping: Mapping) -> DetokenizingBody {
        detokenizer_with_inner(mapping, Body::empty())
    }

    #[test]
    fn response_detokenizer_carries_trailing_utf8_across_frames() {
        let secret = "sk-ant-api03-response-carry-abcDEF123456";
        let outcome = honmoon_core::redact(
            secret,
            b"response-body-test-salt",
            honmoon_core::DEFAULT_MIN_PII_SEVERITY,
        );
        let placeholder = outcome.text;
        let mut body = detokenizer(outcome.mapping);
        let korean = "한".as_bytes();

        let mut first = b"before ".to_vec();
        first.extend_from_slice(&korean[..2]);
        let first_output = body.transform_data(Bytes::from(first));
        assert_eq!(&first_output[..], b"before ");
        assert_eq!(body.carry, korean[..2]);

        let mut second = vec![korean[2]];
        second.extend_from_slice(placeholder.as_bytes());
        second.extend_from_slice(b" after");
        let mut restored = first_output.to_vec();
        restored.extend_from_slice(&body.transform_data(Bytes::from(second)));
        if let Some(final_bytes) = body.finish_bytes() {
            restored.extend_from_slice(&final_bytes);
        }
        assert_eq!(
            String::from_utf8(restored).unwrap(),
            format!("before 한{secret} after")
        );
    }

    #[test]
    fn response_detokenizer_flushes_carry_and_pending_text_before_binary_passthrough() {
        let mut body = detokenizer(Mapping::new());
        let mut first = b"<<hs:".to_vec();
        first.extend_from_slice(&"한".as_bytes()[..2]);
        assert!(body.transform_data(Bytes::from(first)).is_empty());

        let output = body.transform_data(Bytes::from_static(b"\xffbinary"));
        let mut expected = b"<<hs:".to_vec();
        expected.extend_from_slice(&"한".as_bytes()[..2]);
        expected.extend_from_slice(b"\xffbinary");
        assert_eq!(&output[..], &expected);
        assert!(body.passthrough);
        assert!(body.finish_bytes().is_none());
    }

    #[test]
    fn response_detokenizer_flushes_pending_text_then_passes_binary_through() {
        let mut body = detokenizer(Mapping::new());
        assert!(body.transform_data(Bytes::from_static(b"<<hs:")).is_empty());

        let binary = Bytes::from_static(b"\xff\x00binary");
        let output = body.transform_data(binary.clone());
        assert_eq!(&output[..], b"<<hs:\xff\x00binary");
        assert!(body.passthrough);

        let rest = Bytes::from_static(b"\xfe<<hs:unchanged>>");
        assert_eq!(body.transform_data(rest.clone()), rest);
        assert!(body.finish_bytes().is_none());
    }

    #[tokio::test]
    async fn response_detokenizer_flushes_partial_placeholder_before_trailers() {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-checksum", "preserved".parse().unwrap());
        let frames = vec![
            Ok(Frame::data(Bytes::from_static(b"prefix <<hs:"))),
            Ok(Frame::trailers(trailers.clone())),
        ];
        let mut body = detokenizer_with_inner(Mapping::new(), scripted_body(frames));

        let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(&first[..], b"prefix ");
        let flushed = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(&flushed[..], b"<<hs:");
        let preserved = body
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_trailers()
            .unwrap();
        assert_eq!(preserved, trailers);
        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn response_detokenizer_propagates_inner_error_after_partial_output() {
        let frames = vec![
            Ok(Frame::data(Bytes::from_static(b"prefix <<hs:"))),
            Err(hudsucker::Error::Decode),
        ];
        let mut body = detokenizer_with_inner(Mapping::new(), scripted_body(frames));

        let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(&first[..], b"prefix ");
        assert!(matches!(
            body.frame().await.unwrap(),
            Err(hudsucker::Error::Decode)
        ));
    }

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
    fn strict_redaction_decode_rejects_unsupported_or_malformed_encoding() {
        let plain = b"plaintext secret";
        assert!(decode_for_redaction(Some("br"), plain).is_none());
        assert!(decode_for_redaction(Some("gzip"), plain).is_none());

        let compressed = gzip(plain);
        assert_eq!(
            decode_for_redaction(Some("gzip"), &compressed)
                .expect("valid gzip")
                .as_ref(),
            plain
        );
    }

    #[test]
    fn strict_redaction_decode_supports_gzip_alias_and_both_deflate_formats() {
        use std::io::Write;

        let plain = b"placeholder <<hs:codec-test>>";
        let compressed = gzip(plain);
        assert_eq!(
            decode_for_redaction(Some("x-gzip"), &compressed)
                .expect("x-gzip")
                .as_ref(),
            plain
        );

        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zlib.write_all(plain).unwrap();
        let zlib = zlib.finish().unwrap();
        assert_eq!(
            decode_for_redaction(Some("deflate"), &zlib)
                .expect("zlib deflate")
                .as_ref(),
            plain
        );

        let mut raw =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        raw.write_all(plain).unwrap();
        let raw = raw.finish().unwrap();
        assert_eq!(
            decode_for_redaction(Some("deflate"), &raw)
                .expect("raw deflate")
                .as_ref(),
            plain
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
            Buffered::Complete { bytes, trailers } => {
                assert_eq!(&bytes[..], b"small body");
                assert!(trailers.is_none(), "no trailers were sent");
            }
            Buffered::Overflow { .. } => panic!("small body must not overflow"),
        }
    }

    /// A chunked request can carry the `Content-Digest` its signature covers in
    /// a trailer. Buffering it for the scan must not consume the trailer frame,
    /// or `--signed-body forward` forwards a request the client never signed.
    #[tokio::test]
    async fn unknown_length_body_within_cap_keeps_its_trailers() {
        let mut sent = HeaderMap::new();
        sent.insert("content-digest", "sha-256=:ZGlnZXN0:".parse().unwrap());
        let body = scripted_body(vec![
            Ok(Frame::data(Bytes::from_static(b"signed body"))),
            Ok(Frame::trailers(sent.clone())),
        ]);

        match buffer_up_to(body, MAX_INSPECT_BODY).await.expect("read") {
            Buffered::Complete { bytes, trailers } => {
                assert_eq!(&bytes[..], b"signed body");
                assert_eq!(trailers.expect("trailers buffered"), sent);
            }
            Buffered::Overflow { .. } => panic!("small body must not overflow"),
        }
    }

    #[tokio::test]
    async fn rebuilt_buffered_body_replays_data_then_trailers() {
        let mut sent = HeaderMap::new();
        sent.insert("content-digest", "sha-256=:ZGlnZXN0:".parse().unwrap());
        let mut body = buffered_body(Bytes::from_static(b"signed body"), Some(sent.clone()));

        let data = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(&data[..], b"signed body");
        let replayed = body
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_trailers()
            .unwrap();
        assert_eq!(replayed, sent);
        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn oversized_unknown_length_body_streams_through_intact() {
        let big = vec![b'a'; MAX_INSPECT_BODY + 10];
        let body = Body::from(big.clone());
        match buffer_up_to(body, MAX_INSPECT_BODY).await.expect("read") {
            Buffered::Complete { .. } => panic!("oversized body must overflow"),
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

    /// `HeaderMap::remove` takes the whole entry, so a forbidden name sent
    /// several times leaves no later value behind — the case a
    /// remove-the-first-match filter would get wrong.
    #[tokio::test]
    async fn trailer_filter_removes_every_value_of_a_repeated_forbidden_name() {
        let mut sent = HeaderMap::new();
        sent.append("set-cookie", "a=1".parse().unwrap());
        sent.append("set-cookie", "b=2".parse().unwrap());
        sent.insert("x-note", "kept".parse().unwrap());

        let collected = trailer_filtered_body(
            buffered_body(Bytes::from_static(b"body"), Some(sent)),
            &HeaderMap::new(),
            "localhost",
        )
        .collect()
        .await
        .expect("collect filtered body");
        let trailers = collected
            .trailers()
            .cloned()
            .expect("x-note keeps the frame");
        assert_eq!(trailers.get_all("set-cookie").iter().count(), 0);
        assert_eq!(
            trailers.get("x-note").map(|v| v.as_bytes()),
            Some(&b"kept"[..])
        );
        assert_eq!(&collected.to_bytes()[..], b"body");
    }

    /// A trailer section with nothing left after filtering is not forwarded as
    /// an empty frame — and the data frames ahead of it are untouched.
    #[tokio::test]
    async fn trailer_filter_drops_a_frame_it_empties_and_keeps_the_data() {
        let mut sent = HeaderMap::new();
        sent.insert("transfer-encoding", "chunked".parse().unwrap());
        let body = scripted_body(vec![
            Ok(Frame::data(Bytes::from_static(b"one"))),
            Ok(Frame::data(Bytes::from_static(b"two"))),
            Ok(Frame::trailers(sent)),
        ]);

        let collected = trailer_filtered_body(body, &HeaderMap::new(), "localhost")
            .collect()
            .await
            .expect("collect filtered body");
        assert!(
            collected.trailers().is_none(),
            "an emptied trailer section must not be forwarded as an empty frame"
        );
        assert_eq!(&collected.to_bytes()[..], b"onetwo");
    }

    /// A zero-length body yields no data frame at all (`buffered_body` documents
    /// this), so the trailer frame is the *first* frame the filter sees — an
    /// empty signed POST carrying only trailers is a real request shape.
    #[tokio::test]
    async fn trailer_filter_handles_a_trailer_frame_with_no_data_frame_before_it() {
        let mut sent = HeaderMap::new();
        sent.insert("transfer-encoding", "chunked".parse().unwrap());
        sent.insert("content-digest", "sha-256=:ZGlnZXN0:".parse().unwrap());

        let collected = trailer_filtered_body(
            buffered_body(Bytes::new(), Some(sent)),
            &HeaderMap::new(),
            "localhost",
        )
        .collect()
        .await
        .expect("collect filtered body");
        let trailers = collected
            .trailers()
            .cloned()
            .expect("content-digest keeps the frame");
        assert!(!trailers.contains_key("transfer-encoding"));
        assert_eq!(
            trailers.get("content-digest").map(|v| v.as_bytes()),
            Some(&b"sha-256=:ZGlnZXN0:"[..]),
            "the digest a signature may cover is not on the forbidden list"
        );
        assert!(collected.to_bytes().is_empty());
    }

    /// `retained_trailer_names` answers ahead of time what the streaming filter
    /// will do, so a `Trailer` header can be written while the header section is
    /// still in hand. The two read one rule, and this pins that they agree:
    /// anything the filter keeps must be named, and anything it drops must not.
    #[tokio::test]
    async fn retained_names_match_the_streaming_filter() {
        let mut sent = HeaderMap::new();
        for (name, value) in [
            ("transfer-encoding", "chunked"),
            ("content-length", "0"),
            ("authorization", "Bearer smuggled"),
            ("x-hop", "nominated"),
            ("content-digest", "sha-256=:ZGlnZXN0:"),
            ("x-note", "kept"),
        ] {
            sent.insert(
                name,
                hudsucker::hyper::header::HeaderValue::from_static(value),
            );
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            CONNECTION,
            hudsucker::hyper::header::HeaderValue::from_static("x-hop"),
        );

        let predicted = retained_trailer_names(&sent, &headers);
        let filtered = trailer_filtered_body(
            buffered_body(Bytes::new(), Some(sent)),
            &headers,
            "localhost",
        )
        .collect()
        .await
        .expect("collect filtered body")
        .trailers()
        .cloned()
        .expect("a surviving trailer keeps the frame");

        let mut predicted: Vec<&str> = predicted.iter().map(HeaderName::as_str).collect();
        let mut actual: Vec<&str> = filtered.keys().map(HeaderName::as_str).collect();
        predicted.sort_unstable();
        actual.sort_unstable();
        assert_eq!(predicted, actual);
        assert_eq!(actual, ["content-digest", "x-note"]);
    }
}
