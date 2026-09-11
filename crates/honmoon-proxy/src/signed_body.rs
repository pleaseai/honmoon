//! Detection of request authentication whose signature **covers the body**.
//!
//! Honmoon holds none of the client's signing credentials, so it cannot re-sign
//! a body it rewrote. When wire redaction would change the payload of such a
//! request, forwarding the original signature over the new bytes makes the
//! upstream reject it with an opaque signature error — [`mitm`](crate::mitm)
//! decides what to do instead, based on what this module detects.
//!
//! Only schemes whose signature actually binds the payload count. A bearer
//! token, Basic auth, or an API-key header authenticates the *caller*, not the
//! bytes, and a bare `Digest`/`Content-Digest`/`Content-MD5` is a stale
//! validator the rewrite path already strips — treating any of those as
//! body-signed would strand ordinary API traffic unredacted.
//!
//! The same line runs one step further in: a presigned URL proves a *request*
//! was signed, and a payload hash proves a body was hashed, without either
//! proving that a signature covers the bytes. Neither counts alone — see
//! `aws_sigv4_signs_body` below.

use std::collections::HashSet;

use hudsucker::hyper::{HeaderMap, Uri, header};

const X_AMZ_CONTENT_SHA256: header::HeaderName =
    header::HeaderName::from_static("x-amz-content-sha256");
const SIGNATURE_INPUT: header::HeaderName = header::HeaderName::from_static("signature-input");
const SIGNATURE: header::HeaderName = header::HeaderName::from_static("signature");

/// A request-authentication scheme whose signature covers the request body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedBodyScheme {
    /// AWS Signature Version 4 (or SigV4A), header-signed or presigned.
    AwsSigV4,
    /// RFC 9421 HTTP Message Signatures covering a body-digest component.
    HttpMessageSignature,
    /// Legacy draft-cavage `Signature` covering a body-digest header.
    CavageSignature,
}

impl SignedBodyScheme {
    /// Stable short label for logs and audit records.
    pub fn label(self) -> &'static str {
        match self {
            Self::AwsSigV4 => "aws-sigv4",
            Self::HttpMessageSignature => "http-message-signature",
            Self::CavageSignature => "cavage-signature",
        }
    }

    /// Noun phrase naming the scheme in the client-facing block message.
    pub fn description(self) -> &'static str {
        match self {
            Self::AwsSigV4 => "an AWS SigV4 signature",
            Self::HttpMessageSignature => "an RFC 9421 message signature over a body digest",
            Self::CavageSignature => "a draft-cavage signature over a body digest",
        }
    }
}

/// Which body-covering signature scheme authenticates this request, if any.
pub fn body_signature_scheme(headers: &HeaderMap, uri: &Uri) -> Option<SignedBodyScheme> {
    if aws_sigv4_signs_body(headers, uri) {
        return Some(SignedBodyScheme::AwsSigV4);
    }
    if message_signature_covers_body_digest(headers) {
        return Some(SignedBodyScheme::HttpMessageSignature);
    }
    if cavage_signature_covers_digest(headers) {
        return Some(SignedBodyScheme::CavageSignature);
    }
    None
}

/// Whether the request carries request-signing authentication whose
/// signature covers headers, regardless of whether it also binds the
/// payload.
///
/// This is a strictly different question from [`body_signature_scheme`]. A
/// SigV4 request that opts out of payload signing with `UNSIGNED-PAYLOAD` /
/// `STREAMING-UNSIGNED-PAYLOAD…` correctly gets `None` there — its body is
/// not signed, so redacting it is safe — but the request is still
/// SigV4-authenticated, and its `SignedHeaders` list may cover headers
/// (`accept-encoding` among them) that Honmoon would otherwise rewrite in
/// place. Mutating those breaks the signature even though the payload was
/// never bound by it, so callers that mutate headers (not the body) must
/// check this predicate instead.
pub fn authentication_signs_headers(headers: &HeaderMap, uri: &Uri) -> bool {
    aws_sigv4_authenticates(headers, uri)
        || message_signature_present(headers)
        || cavage_headers_param_present(headers)
}

/// Headers the wire-redaction rewrite re-frames or drops when it replaces a
/// request body.
///
/// `Content-Length` describes the new bytes and the replacement body is
/// decoded UTF-8 text rather than the client's compressed or chunked
/// representation, so all three have to change with the body — unlike
/// `Accept-Encoding`, which the proxy can simply leave alone. They are also
/// routinely named in a `SignedHeaders` list (an AWS SDK upload signs
/// `content-length`), so they need the same one-definition agreement between
/// rewriting and detection that [`BODY_DIGEST_HEADERS`] has: this is the set
/// [`mitm`](crate::mitm) rewrites and the set it asks
/// [`signed_headers_among`] about.
pub const REWRITTEN_FRAMING_HEADERS: [header::HeaderName; 3] = [
    header::CONTENT_LENGTH,
    header::CONTENT_ENCODING,
    header::TRANSFER_ENCODING,
];

/// Which of `candidates` this request's authentication actually signs, in the
/// order given.
///
/// A signature over a header is broken by rewriting that header just as surely
/// as a body-covering one is broken by rewriting the payload, and honmoon can
/// re-sign neither. [`authentication_signs_headers`] answers the coarser
/// question — is *anything* header-signed — and is deliberately broad, because
/// its only consequence is leaving one header alone. This one drives the same
/// block-or-forward decision as [`body_signature_scheme`], so it parses the
/// covered list instead of assuming: a SigV4 `SignedHeaders` list (from the
/// `Authorization` credential or a presigned `X-Amz-SignedHeaders` query
/// parameter), an RFC 9421 component list under a label `Signature` carries,
/// or a draft-cavage `headers="…"` parameter. Over-inclusion here would refuse
/// redactable traffic under `block` and, worse, forward the secret unredacted
/// under `--signed-body forward`, so a name counts only when one of those
/// lists genuinely holds it.
pub fn signed_headers_among(
    headers: &HeaderMap,
    uri: &Uri,
    candidates: &[header::HeaderName],
) -> Vec<header::HeaderName> {
    candidates
        .iter()
        .filter(|name| header_is_signed(headers, uri, name.as_str()))
        .cloned()
        .collect()
}

/// Whether any recognized scheme's signature covers the header `name`.
fn header_is_signed(headers: &HeaderMap, uri: &Uri, name: &str) -> bool {
    sigv4_signs_header(headers, uri, name)
        || message_signature_covers(headers, |component| component.eq_ignore_ascii_case(name))
        || cavage_signature_covers(headers, |component| component.eq_ignore_ascii_case(name))
}

/// Whether a SigV4 `SignedHeaders` list covers `name`.
fn sigv4_signs_header(headers: &HeaderMap, uri: &Uri, name: &str) -> bool {
    sigv4_signed_header_lists(headers, uri).iter().any(|list| {
        list.split(';')
            .any(|covered| covered.trim().eq_ignore_ascii_case(name))
    })
}

/// Every `SignedHeaders` list the request carries: the `SignedHeaders=`
/// credential parameter of an `AWS4-…` `Authorization`, and the
/// `X-Amz-SignedHeaders` query parameter of a presigned URL.
///
/// The parameter name is anchored to the start of a top-level, comma-separated
/// segment (see [`split_top_level_params`]), so it cannot match inside the
/// `Credential` path or a base64 `Signature` that happens to spell it, and
/// *every* list is returned rather than the first, so a decoy cannot shadow
/// the real parameter.
fn sigv4_signed_header_lists(headers: &HeaderMap, uri: &Uri) -> Vec<String> {
    let mut lists: Vec<String> = header_values(headers, &header::AUTHORIZATION)
        .filter(|value| is_sigv4_authorization(value))
        .flat_map(|value| {
            split_top_level_params(value).filter_map(|segment| {
                // A covered list is lowercase header names, so the lowercased
                // copy serves as both the match and the value.
                let lowered = segment.trim().to_ascii_lowercase();
                let rest = lowered.strip_prefix("signedheaders")?.trim_start();
                Some(rest.strip_prefix('=')?.trim_start().to_owned())
            })
        })
        .collect();
    // The query list counts only on a request that actually carries SigV4.
    // `X-Amz-SignedHeaders` is a bare query parameter any client can append to
    // any URL, and a covered framing header decides block-or-forward: without
    // this gate a crafted `?X-Amz-SignedHeaders=content-length` on an ordinary
    // request would earn a spurious 403 under `block` and, under `forward`,
    // send its unredacted body upstream. The `Authorization` branch above is
    // already gated the same way, and `aws_sigv4_authenticates` is the module's
    // one definition of "this request is SigV4".
    if aws_sigv4_authenticates(headers, uri) {
        lists.extend(query_values(uri, "X-Amz-SignedHeaders").map(decode_percent_separators));
    }
    lists
}

/// A presigned URL carries its `SignedHeaders` list in the query string, where
/// the `;` separators are percent-encoded. Header names are tokens and are
/// never themselves encoded, so restoring the separator is all this list
/// needs — a full percent-decoder would only widen what a crafted query can
/// turn into a separator.
fn decode_percent_separators(value: &str) -> String {
    value.replace("%3B", ";").replace("%3b", ";")
}

/// Whether an `Authorization` field value is a SigV4 credential.
fn is_sigv4_authorization(value: &str) -> bool {
    starts_with_ignore_ascii_case(value, "AWS4-HMAC-SHA256")
        || starts_with_ignore_ascii_case(value, "AWS4-ECDSA-P256-SHA256")
}

/// SigV4 binds the body only when the request carries SigV4 authentication
/// *and* that signature's canonical request hashed the payload.
///
/// The two carriers bind different things, and that difference is the whole of
/// this predicate:
///
/// - A header-signed `Authorization: AWS4-…` always hashes the payload into
///   its canonical request (for non-S3 services the hash is not even sent as a
///   header), so it binds the body unless the request opts out with
///   `UNSIGNED-PAYLOAD` / `STREAMING-UNSIGNED-PAYLOAD…`.
/// - A presigned `X-Amz-Algorithm=AWS4-…` query parameter authenticates the
///   *request*, not the upload: a standard S3 presigned URL puts
///   `UNSIGNED-PAYLOAD` in its canonical request, so nothing binds the bytes
///   unless the request also declares a signed payload in the
///   `x-amz-content-sha256` header — or, when it sends no such header, in the
///   `X-Amz-Content-Sha256` query parameter presigning hoists that header
///   into. The precedence is on [`payload_hash_declarations`].
///
/// Neither a presigned query parameter nor a bare `x-amz-content-sha256`
/// counts on its own. Both used to: a presigned upload carrying a secret was
/// refused under the default `block` even though its signature never covered
/// the body, and a payload hash — an integrity header any client sets freely,
/// with no AWS authentication anywhere on the request — classified the request
/// as signed, which under `--signed-body forward` is what *disables* redaction.
/// Narrowing buys that back at the price of a false negative on a body-signing
/// scheme whose only trace is a payload hash; such a scheme's signature breaks
/// under redaction exactly as any scheme this module does not recognize already
/// does. See ADR-0006.
fn aws_sigv4_signs_body(headers: &HeaderMap, uri: &Uri) -> bool {
    let presigned = sigv4_presigned_query(uri);
    let declared = payload_hash_declarations(headers, uri, presigned);
    if declared.iter().copied().any(declares_unsigned_payload) {
        return false;
    }
    if header_str(headers, &header::AUTHORIZATION).is_some_and(is_sigv4_authorization) {
        return true;
    }
    presigned && declared.iter().copied().any(declares_signed_payload)
}

/// What the request declares about its payload hash, read from the carrier the
/// verifier actually reads.
///
/// The `x-amz-content-sha256` header is that carrier and is authoritative: it
/// is the value a signer hashes into the canonical request, so a query
/// parameter must not be able to contradict it — letting a crafted
/// `?X-Amz-Content-Sha256=UNSIGNED-PAYLOAD` downgrade a header-signed upload
/// would redact a body its signature does covers and break it upstream. Every
/// field value counts, so a duplicate header cannot hide the one that matters.
///
/// The query parameter is consulted only when the header is absent *and* the
/// request is presigned, because that is the one case where it is the signer's
/// own declaration rather than a bare query argument: presigning hoists the
/// `x-amz-…` headers it signs into the query string, so a presigned upload
/// that bound its payload may carry the hash there and send no header at all.
/// Reading it keeps that upload from being redacted into an opaque upstream
/// signature failure; ignoring it would be the `UNSIGNED-PAYLOAD` conclusion
/// for a request that declared the opposite.
fn payload_hash_declarations<'a>(
    headers: &'a HeaderMap,
    uri: &'a Uri,
    presigned: bool,
) -> Vec<&'a str> {
    let from_header: Vec<&str> = header_values(headers, &X_AMZ_CONTENT_SHA256)
        .filter(|value| !value.is_empty())
        .collect();
    if !from_header.is_empty() || !presigned {
        return from_header;
    }
    query_values(uri, "X-Amz-Content-Sha256")
        .filter(|value| !value.is_empty())
        .collect()
}

/// Whether an `x-amz-content-sha256` value declares the payload explicitly out
/// of the signature.
fn declares_unsigned_payload(hash: &str) -> bool {
    hash.eq_ignore_ascii_case("UNSIGNED-PAYLOAD")
        || starts_with_ignore_ascii_case(hash, "STREAMING-UNSIGNED-PAYLOAD")
}

/// The `x-amz-content-sha256` values that declare a payload signed per chunk
/// rather than hashed up front. Spelled out rather than matched by a
/// `STREAMING-AWS4-` prefix: the prefix would also accept an invented
/// `STREAMING-AWS4-…` value, and since this is the presigned path's evidence
/// of payload signing, accepting one would refuse a redactable request under
/// `block` and forward its secret unredacted under `forward`.
const STREAMING_SIGNED_PAYLOAD_MARKERS: [&str; 4] = [
    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
    "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD",
    "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER",
];

/// Whether an `x-amz-content-sha256` value is evidence that the signer bound
/// the body: a hex SHA-256 of the payload, or one of
/// [`STREAMING_SIGNED_PAYLOAD_MARKERS`]. The hash is length-checked because a
/// short hex string is not a SHA-256, and the `STREAMING-UNSIGNED-PAYLOAD…`
/// markers never reach here — [`declares_unsigned_payload`] rejects them
/// first.
fn declares_signed_payload(hash: &str) -> bool {
    let hex_sha256 = hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit());
    hex_sha256
        || STREAMING_SIGNED_PAYLOAD_MARKERS
            .iter()
            .any(|marker| hash.eq_ignore_ascii_case(marker))
}

/// Whether the request carries SigV4 authentication at all — header-signed
/// or presigned — irrespective of whether the payload itself is signed.
fn aws_sigv4_authenticates(headers: &HeaderMap, uri: &Uri) -> bool {
    header_str(headers, &header::AUTHORIZATION).is_some_and(is_sigv4_authorization)
        || sigv4_presigned_query(uri)
}

/// Whether the query string carries a presigned SigV4 `X-Amz-Algorithm`, which
/// is where a presigned URL names the algorithm instead of `Authorization`.
fn sigv4_presigned_query(uri: &Uri) -> bool {
    query_values(uri, "X-Amz-Algorithm").any(|value| starts_with_ignore_ascii_case(value, "AWS4-"))
}

/// The raw value of every query parameter named `name`, matched
/// case-insensitively. Values are left percent-encoded: the `X-Amz-…`
/// parameters this module reads carry a hex hash, an algorithm name, or an
/// uppercase marker, none of which a signer encodes, and decoding more than a
/// caller needs only widens what a crafted query can turn into a separator
/// (see [`decode_percent_separators`]).
fn query_values<'a>(uri: &'a Uri, name: &'static str) -> impl Iterator<Item = &'a str> + 'a {
    uri.query().into_iter().flat_map(move |query| {
        query.split('&').filter_map(move |pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            key.eq_ignore_ascii_case(name).then_some(value)
        })
    })
}

/// RFC 9421: the signature covers the body only when some `Signature-Input`
/// member's component list names one of [`BODY_DIGEST_HEADERS`] *and*
/// `Signature` also carries an entry under that exact member's label.
///
/// `Signature-Input` and `Signature` are both dictionaries keyed by the same
/// labels (e.g. `sig1`); a member of `Signature-Input` is only actually
/// signed when `Signature` carries an entry under that same label — naming
/// a body digest in one member's component list says nothing about a
/// *different* member that happens to be the one actually signed. Both
/// fields may legally repeat across multiple field values, so every value of
/// both is scanned, and labels are matched across all of them rather than
/// only within a single field value.
fn message_signature_covers_body_digest(headers: &HeaderMap) -> bool {
    message_signature_covers(headers, is_body_digest_header)
}

/// RFC 9421: whether some member's component list names a component `covered`
/// accepts, under a label `Signature` actually carries.
///
/// The label matching, and why it is required, is described on
/// [`message_signature_covers_body_digest`] — the only caller that asks about
/// the body. Callers asking about a header pass their own predicate.
fn message_signature_covers(headers: &HeaderMap, covered: impl Fn(&str) -> bool + Copy) -> bool {
    let signed_labels: HashSet<String> = header_values(headers, &SIGNATURE)
        .flat_map(signature_member_labels)
        .collect();
    if signed_labels.is_empty() {
        return false;
    }
    header_values(headers, &SIGNATURE_INPUT)
        .flat_map(|value| signature_input_labels_covering(value, covered))
        .any(|label| signed_labels.contains(&label))
}

/// RFC 9421: whether the request carries a `Signature-Input` + `Signature`
/// pair at all, regardless of which components the list names. Any such pair
/// signs the headers named in its component list — covering headers is the
/// whole point of the scheme — so this is broader than
/// [`message_signature_covers_body_digest`], which only cares about the
/// body.
///
/// This is deliberately kept broad, unlike the strict per-label matching
/// above: this predicate only gates whether callers may mutate request
/// headers (over-inclusion is fail-safe — it just means a header is left
/// alone), while over-inclusion in the body-digest predicate would let an
/// unsigned body slip through redaction as if it were signed. Do not tighten
/// this one to require a matching label merely for symmetry with the other.
fn message_signature_present(headers: &HeaderMap) -> bool {
    header_present(headers, &SIGNATURE) && header_present(headers, &SIGNATURE_INPUT)
}

/// The dictionary-member labels (e.g. `sig1`) inside a `Signature-Input`
/// field value whose parenthesised component list names a covered component.
///
/// A member is `label=value`, members separated by a top-level comma (see
/// [`split_top_level_params`]). The label is the token before the member's
/// first `=`, trimmed of whitespace. Labels are normalized to lowercase for
/// the comparison in [`message_signature_covers`] — dictionary
/// keys are case-sensitive tokens per Structured Fields, but signature labels
/// are lowercase in practice, and both sides of that comparison are
/// normalized identically, so this cannot turn a mismatch into a false match.
fn signature_input_labels_covering<'a>(
    value: &'a str,
    covered: impl Fn(&str) -> bool + 'a,
) -> impl Iterator<Item = String> + 'a {
    split_top_level_params(value).filter_map(move |member| {
        let (label, rest) = member.split_once('=')?;
        let label = label.trim();
        if label.is_empty() || !signature_input_lists_component(rest, &covered) {
            return None;
        }
        Some(label.to_ascii_lowercase())
    })
}

/// The dictionary-member labels present in a `Signature` field value, e.g.
/// `sig1` and `sig2` in `sig1=:abc:, sig2=:def:`. Normalized to lowercase to
/// match [`signature_input_labels_covering`].
fn signature_member_labels(value: &str) -> impl Iterator<Item = String> + '_ {
    split_top_level_params(value).filter_map(|member| {
        let (label, _) = member.split_once('=')?;
        let label = label.trim();
        (!label.is_empty()).then(|| label.to_ascii_lowercase())
    })
}

/// Header names whose value is a digest of the body.
///
/// A signature covering any of them binds the body just as directly as one
/// covering the payload itself: the digest cannot survive a rewrite, and the
/// rewrite path strips all four as stale validators, so the signature is
/// broken outright rather than merely mismatched.
///
/// This is the single definition of that set: [`mitm`](crate::mitm) strips
/// exactly these headers when it rewrites a body, and this module treats a
/// signature over any of them as body-binding. The two readings have to agree
/// — a header stripped but not detected is precisely the opaque upstream
/// rejection this module exists to prevent — so they share one constant
/// rather than two lists and a comment asking future edits to keep them
/// aligned.
pub const BODY_DIGEST_HEADERS: [header::HeaderName; 4] = [
    header::HeaderName::from_static("digest"),
    header::HeaderName::from_static("content-digest"),
    header::HeaderName::from_static("content-md5"),
    header::HeaderName::from_static("repr-digest"),
];

fn is_body_digest_header(name: &str) -> bool {
    BODY_DIGEST_HEADERS
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate.as_str()))
}

/// Whether the parenthesised component list of a `Signature-Input` member —
/// not the member's other `;param=value` metadata — names a quoted component
/// that `covered` accepts.
///
/// A single-pass, quote-aware scan: paren depth is tracked only outside a
/// quoted string, since a `(` or `)` inside a quoted parameter value (e.g. a
/// `tag` crafted to contain `("content-digest")`) is not a real group
/// delimiter. Backslash escapes inside quoted strings are honored so an
/// escaped quote doesn't end the string early.
///
/// A quoted string counts only when it closes while depth >= 1 *and* it is a
/// component identifier rather than a component's own parameter value. Inside
/// the list an item is `"name";param=value`, so
/// `("@method" "@query-param";name="content-digest")` signs a query parameter
/// that happens to be called `content-digest` — not the `Content-Digest`
/// field, and not the body. Counting it would classify a redactable request
/// as body-signed, which leaks the secret under `--signed-body forward`.
/// RFC 8941 puts no whitespace around a parameter's `=`, but whitespace is
/// tolerated here anyway: treating one more quoted string as a parameter
/// value can only make this predicate stricter, which is the safe direction.
fn signature_input_lists_component(value: &str, covered: impl Fn(&str) -> bool) -> bool {
    let mut depth: u32 = 0;
    let mut in_quote = false;
    let mut escaped = false;
    let mut after_equals = false;
    let mut is_param_value = false;
    let mut current = String::new();
    for ch in value.chars() {
        if in_quote {
            if escaped {
                current.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_quote = false;
                if depth >= 1 && !is_param_value && covered(&current) {
                    return true;
                }
                current.clear();
            } else {
                current.push(ch);
            }
        } else {
            match ch {
                '"' => {
                    in_quote = true;
                    is_param_value = after_equals;
                    after_equals = false;
                }
                '(' => {
                    depth += 1;
                    after_equals = false;
                }
                ')' => {
                    depth = depth.saturating_sub(1);
                    after_equals = false;
                }
                '=' => after_equals = true,
                _ if ch.is_ascii_whitespace() => {}
                _ => after_equals = false,
            }
        }
    }
    false
}

/// draft-cavage: the signature covers the body only when its `headers="…"`
/// list names a body digest header. The signature may be carried as a
/// standalone `Signature` header or as `Authorization: Signature …` (either
/// field may in principle repeat), and the `headers` parameter's grammar
/// permits whitespace around `=`.
fn cavage_signature_covers_digest(headers: &HeaderMap) -> bool {
    cavage_signature_covers(headers, is_body_digest_header)
}

/// draft-cavage: whether some `headers="…"` parameter's covered list names a
/// header `covered` accepts, from either carrier field.
fn cavage_signature_covers(headers: &HeaderMap, covered: impl Fn(&str) -> bool) -> bool {
    let candidates = header_values(headers, &SIGNATURE)
        .chain(header_values(headers, &header::AUTHORIZATION).filter_map(strip_signature_scheme));
    candidates
        .flat_map(cavage_headers_params)
        .any(|list| list.split_whitespace().any(&covered))
}

/// draft-cavage: whether the request carries a `headers="…"` auth-param at
/// all — via a standalone `Signature` header or `Authorization: Signature …`
/// — regardless of which headers its covered list names. Any such parameter
/// signs the headers it lists, which is broader than
/// [`cavage_signature_covers_digest`]'s narrower body-digest question.
fn cavage_headers_param_present(headers: &HeaderMap) -> bool {
    let candidates = header_values(headers, &SIGNATURE)
        .chain(header_values(headers, &header::AUTHORIZATION).filter_map(strip_signature_scheme));
    candidates.flat_map(cavage_headers_params).next().is_some()
}

/// Strip a leading `Signature` scheme token (case-insensitive, followed by
/// whitespace) from an `Authorization` field value, e.g.
/// `Signature keyId="…",headers="…"` → `keyId="…",headers="…"`.
fn strip_signature_scheme(value: &str) -> Option<&str> {
    if !starts_with_ignore_ascii_case(value, "Signature") {
        return None;
    }
    let rest = &value["Signature".len()..];
    if !rest.starts_with(|c: char| c.is_whitespace()) {
        return None;
    }
    Some(rest.trim_start())
}

/// Every `headers="…"` auth-param value in a cavage (or Authorization-carried
/// cavage) signature value, tolerating optional whitespace around `=`.
///
/// Not a full auth-param parser: it only needs this one parameter's quoted
/// list. Two things it must get right, though. The name is anchored to the
/// start of a comma-separated segment, so it cannot match inside an unrelated
/// parameter — a `keyId` of `"webhook-headers-key"`, or a base64 `signature`
/// that happens to spell it. And *every* match is yielded rather than the
/// first, so a decoy segment crafted inside another parameter's quoted value
/// cannot shadow the real parameter. Missing either one reports a signed body
/// as unsigned, which is the redaction-then-rejection this module exists to
/// prevent. The covered list is space-separated, so splitting on `,` never
/// splits the value itself.
fn cavage_headers_params(value: &str) -> impl Iterator<Item = String> + '_ {
    split_top_level_params(value).filter_map(|segment| {
        let lowered = segment.trim().to_ascii_lowercase();
        let rest = lowered.strip_prefix("headers")?.trim_start();
        let rest = rest.strip_prefix('=')?.trim_start();
        let rest = rest.strip_prefix('"')?;
        rest.split_once('"').map(|(covered, _)| covered.to_owned())
    })
}

/// Split `value` into its top-level, comma-separated members, only splitting
/// on a `,` that sits outside a double-quoted value and outside a
/// parenthesised group.
///
/// A naive `str::split(',')` lets a decoy segment hide inside another
/// member's quoted value — e.g. a `keyId` crafted as `"x,headers=\"host\""`,
/// or an RFC 9421 component list's own `;name="a,b"` parameter — and get
/// mistaken for a genuine top-level boundary. This single-pass scan tracks
/// quote state (with backslash-escape handling, so an escaped quote doesn't
/// end the string early) and paren depth, and only treats a comma as a
/// boundary while outside both. Paren tracking is only relevant to RFC 9421
/// `Signature-Input` values, whose component list is itself
/// parenthesised; cavage callers pass values that contain no parens, so
/// depth simply stays 0 there and behavior is unchanged.
fn split_top_level_params(value: &str) -> impl Iterator<Item = &str> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut in_quote = false;
    let mut escaped = false;
    let mut depth: u32 = 0;
    for (idx, ch) in value.char_indices() {
        if in_quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_quote = false;
            }
        } else {
            match ch {
                '"' => in_quote = true,
                '(' => depth += 1,
                ')' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    segments.push(&value[start..idx]);
                    start = idx + ch.len_utf8();
                }
                _ => {}
            }
        }
    }
    segments.push(&value[start..]);
    segments.into_iter()
}

/// Whether `name` is present with a non-empty value in any field value.
fn header_present(headers: &HeaderMap, name: &header::HeaderName) -> bool {
    header_values(headers, name).any(|value| !value.is_empty())
}

/// The trimmed UTF-8 value of every field value named `name`, skipping any
/// that are not valid UTF-8.
fn header_values<'a>(
    headers: &'a HeaderMap,
    name: &header::HeaderName,
) -> impl Iterator<Item = &'a str> + use<'a> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::trim)
}

/// The trimmed UTF-8 value of `name`, if it is present and not binary.
fn header_str<'a>(headers: &'a HeaderMap, name: &header::HeaderName) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
}

fn starts_with_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scheme(headers: &[(&str, &str)], uri: &str) -> Option<SignedBodyScheme> {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.insert(
                header::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
                header::HeaderValue::from_str(value).expect("header value"),
            );
        }
        body_signature_scheme(&map, &uri.parse::<Uri>().expect("uri"))
    }

    fn signs_headers(headers: &[(&str, &str)], uri: &str) -> bool {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.insert(
                header::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
                header::HeaderValue::from_str(value).expect("header value"),
            );
        }
        authentication_signs_headers(&map, &uri.parse::<Uri>().expect("uri"))
    }

    /// The framing headers the rewrite would change that this request signs,
    /// as the names [`mitm`](crate::mitm) puts in its block message.
    fn signed_framing(headers: &[(&str, &str)], uri: &str) -> Vec<String> {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.insert(
                header::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
                header::HeaderValue::from_str(value).expect("header value"),
            );
        }
        signed_headers_among(
            &map,
            &uri.parse::<Uri>().expect("uri"),
            &REWRITTEN_FRAMING_HEADERS,
        )
        .iter()
        .map(|name| name.as_str().to_owned())
        .collect()
    }

    /// The case this predicate exists for: a SigV4 request that opts out of
    /// payload signing is not body-signed (redacting the body is safe), but
    /// its `Authorization` still signs headers — so overwriting a header like
    /// `Accept-Encoding` would still break the signature.
    #[test]
    fn sigv4_unsigned_payload_still_signs_headers() {
        let headers = [
            (
                "authorization",
                "AWS4-HMAC-SHA256 Credential=AKIA/20260907/us-east-1/s3/aws4_request, \
                 SignedHeaders=host;x-amz-date;accept-encoding, Signature=abc",
            ),
            ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
        ];
        let uri = "https://s3.amazonaws.com/b/k";
        assert_eq!(scheme(&headers, uri), None, "body should not be signed");
        assert!(
            signs_headers(&headers, uri),
            "headers should still be signed"
        );
    }

    #[test]
    fn bearer_token_does_not_sign_headers() {
        assert!(!signs_headers(
            &[("authorization", "Bearer sk-live-token")],
            "https://api.example.com/v1"
        ));
    }

    #[test]
    fn sigv4_authorization_signs_the_body() {
        let auth = "AWS4-HMAC-SHA256 Credential=AKIA/20260907/us-east-1/s3/aws4_request, \
                    SignedHeaders=host;x-amz-date, Signature=abc";
        assert_eq!(
            scheme(&[("authorization", auth)], "https://s3.amazonaws.com/b/k"),
            Some(SignedBodyScheme::AwsSigV4)
        );
    }

    #[test]
    fn sigv4_unsigned_payload_leaves_the_body_uncovered() {
        let auth = "AWS4-HMAC-SHA256 Credential=AKIA/20260907/us-east-1/s3/aws4_request, \
                    SignedHeaders=host;x-amz-date, Signature=abc";
        for marker in ["UNSIGNED-PAYLOAD", "STREAMING-UNSIGNED-PAYLOAD-TRAILER"] {
            assert_eq!(
                scheme(
                    &[("authorization", auth), ("x-amz-content-sha256", marker)],
                    "https://s3.amazonaws.com/b/k"
                ),
                None,
                "{marker}"
            );
        }
    }

    /// A standard S3 presigned URL signs the *request*, not the upload: its
    /// canonical request uses `UNSIGNED-PAYLOAD`, so the bytes stay redactable.
    /// The URL is still SigV4-authenticated, so its `SignedHeaders` list keeps
    /// protecting the headers it names.
    #[test]
    fn presigned_sigv4_query_alone_leaves_the_body_uncovered() {
        let uri = "https://s3.amazonaws.com/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=60";
        assert_eq!(scheme(&[], uri), None, "body should not be signed");
        assert!(signs_headers(&[], uri), "headers should still be signed");
    }

    /// A presigned URL that also declares a signed payload — a hex SHA-256, or
    /// one of the per-chunk signing markers — does bind the bytes.
    #[test]
    fn presigned_sigv4_with_a_signed_payload_signs_the_body() {
        let hex_sha256 = "a".repeat(64);
        let hashes = [hex_sha256.as_str()]
            .into_iter()
            .chain(STREAMING_SIGNED_PAYLOAD_MARKERS);
        for hash in hashes {
            assert_eq!(
                scheme(
                    &[("x-amz-content-sha256", hash)],
                    "https://s3.amazonaws.com/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256"
                ),
                Some(SignedBodyScheme::AwsSigV4),
                "{hash}"
            );
        }
    }

    /// Presigning moves a signed header into the query string, so the payload
    /// hash is read from `X-Amz-Content-Sha256` too.
    #[test]
    fn presigned_sigv4_payload_hash_in_the_query_signs_the_body() {
        let hex_sha256 = "a".repeat(64);
        assert_eq!(
            scheme(
                &[],
                &format!(
                    "https://s3.amazonaws.com/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256\
                     &X-Amz-Content-Sha256={hex_sha256}"
                )
            ),
            Some(SignedBodyScheme::AwsSigV4)
        );
    }

    /// A hoisted opt-out is read like a header one when there is no header to
    /// read — which is the only case the query carrier speaks for.
    #[test]
    fn hoisted_unsigned_payload_marker_leaves_the_body_uncovered() {
        assert_eq!(
            scheme(
                &[],
                "https://s3.amazonaws.com/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256\
                 &X-Amz-Content-Sha256=UNSIGNED-PAYLOAD"
            ),
            None
        );
    }

    /// The header is the carrier the verifier reads, so a query parameter
    /// cannot contradict it in either direction. Were it able to, an appended
    /// `?X-Amz-Content-Sha256=UNSIGNED-PAYLOAD` would have a signed body
    /// redacted and broken upstream.
    #[test]
    fn a_query_payload_hash_never_overrides_the_header() {
        let hex_sha256 = "a".repeat(64);
        assert_eq!(
            scheme(
                &[("x-amz-content-sha256", hex_sha256.as_str())],
                "https://s3.amazonaws.com/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256\
                 &X-Amz-Content-Sha256=UNSIGNED-PAYLOAD"
            ),
            Some(SignedBodyScheme::AwsSigV4),
            "header hash against a query opt-out"
        );
        assert_eq!(
            scheme(
                &[("x-amz-content-sha256", "UNSIGNED-PAYLOAD")],
                &format!(
                    "https://s3.amazonaws.com/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256\
                     &X-Amz-Content-Sha256={hex_sha256}"
                )
            ),
            None,
            "header opt-out against a query hash"
        );
    }

    /// Hoisting is a presigning behavior, so the query carrier is read only on
    /// a presigned request: on a header-signed one, a query parameter of that
    /// name is a bare query argument the verifier never reads as the payload
    /// hash, and must not turn a body-signed request into a redactable one.
    #[test]
    fn a_query_payload_hash_is_ignored_on_a_header_signed_request() {
        let auth = "AWS4-HMAC-SHA256 Credential=AKIA/20260907/us-east-1/s3/aws4_request, \
                    SignedHeaders=host;x-amz-date, Signature=abc";
        assert_eq!(
            scheme(
                &[("authorization", auth)],
                "https://s3.amazonaws.com/b/k?X-Amz-Content-Sha256=UNSIGNED-PAYLOAD"
            ),
            Some(SignedBodyScheme::AwsSigV4)
        );
    }

    /// A payload hash is an integrity header, not a signature: with no SigV4
    /// authentication anywhere on the request it says nothing about who, if
    /// anyone, signed those bytes — and trusting a header the client fully
    /// controls is what would disable redaction under `--signed-body forward`.
    #[test]
    fn bare_hex_payload_hash_leaves_the_body_uncovered() {
        let hex_sha256 = "a".repeat(64);
        let headers = [("x-amz-content-sha256", hex_sha256.as_str())];
        let uri = "https://s3.amazonaws.com/b/k";
        assert_eq!(scheme(&headers, uri), None, "body should not be signed");
        assert!(!signs_headers(&headers, uri), "nothing signs headers");
    }

    /// The presigned path's evidence has to look like a payload hash: a short
    /// hex string, or an opaque value, is not a SHA-256 of the body.
    #[test]
    fn presigned_sigv4_needs_a_payload_hash_shaped_value() {
        for hash in ["abc123", "not-a-hash", "STREAMING-AWS4-GARBAGE", ""] {
            assert_eq!(
                scheme(
                    &[("x-amz-content-sha256", hash)],
                    "https://s3.amazonaws.com/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256"
                ),
                None,
                "{hash:?}"
            );
        }
    }

    /// A presigned URL that spells out the opt-out is the explicit form of the
    /// same conclusion.
    #[test]
    fn presigned_sigv4_unsigned_payload_leaves_the_body_uncovered() {
        for marker in ["UNSIGNED-PAYLOAD", "STREAMING-UNSIGNED-PAYLOAD-TRAILER"] {
            assert_eq!(
                scheme(
                    &[("x-amz-content-sha256", marker)],
                    "https://s3.amazonaws.com/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256"
                ),
                None,
                "{marker}"
            );
        }
    }

    #[test]
    fn message_signature_needs_a_content_digest_component() {
        assert_eq!(
            scheme(
                &[
                    (
                        "signature-input",
                        r#"sig1=("@method" "@authority" "content-digest");created=1618884473"#
                    ),
                    ("signature", "sig1=:abc:")
                ],
                "https://api.example.com/v1"
            ),
            Some(SignedBodyScheme::HttpMessageSignature)
        );
        assert_eq!(
            scheme(
                &[
                    (
                        "signature-input",
                        r#"sig1=("@method" "@authority");created=1618884473"#
                    ),
                    ("signature", "sig1=:abc:")
                ],
                "https://api.example.com/v1"
            ),
            None
        );
    }

    #[test]
    fn message_signature_input_alone_without_a_signature_header_is_not_detected() {
        assert_eq!(
            scheme(
                &[(
                    "signature-input",
                    r#"sig1=("@method" "@authority" "content-digest");created=1618884473"#
                )],
                "https://api.example.com/v1"
            ),
            None
        );
    }

    #[test]
    fn message_signature_input_repeated_field_value_is_scanned() {
        let mut map = HeaderMap::new();
        map.append(
            SIGNATURE_INPUT,
            header::HeaderValue::from_static(r#"sig1=("@method" "@authority");created=1618884473"#),
        );
        map.append(
            SIGNATURE_INPUT,
            header::HeaderValue::from_static(
                r#"sig2=("@method" "@authority" "content-digest");created=1618884474"#,
            ),
        );
        // `sig2` — the member whose component list names `content-digest` — has to
        // carry a `Signature` entry of its own, or the component says nothing about
        // what was actually signed. Only the *second* `Signature-Input` field value
        // names it, so a scan that stopped at the first value would find nothing.
        map.insert(
            SIGNATURE,
            header::HeaderValue::from_static("sig1=:abc:, sig2=:def:"),
        );
        assert_eq!(
            body_signature_scheme(&map, &"https://api.example.com/v1".parse::<Uri>().unwrap()),
            Some(SignedBodyScheme::HttpMessageSignature)
        );
    }

    /// A `Signature-Input` parameter (not the covered-component list) that
    /// merely mentions `content-digest` must not be mistaken for coverage —
    /// only a component named inside the `(...)` list counts.
    #[test]
    fn message_signature_param_value_naming_content_digest_does_not_count() {
        assert_eq!(
            scheme(
                &[
                    (
                        "signature-input",
                        r#"sig1=("@method");tag="content-digest""#
                    ),
                    ("signature", "sig1=:abc:")
                ],
                "https://api.example.com/v1"
            ),
            None
        );
    }

    /// Guard against over-tightening: a genuine covered component is still
    /// detected once it sits inside the component list.
    #[test]
    fn message_signature_covered_component_is_still_detected() {
        assert_eq!(
            scheme(
                &[
                    ("signature-input", r#"sig1=("@method" "content-digest")"#),
                    ("signature", "sig1=:abc:")
                ],
                "https://api.example.com/v1"
            ),
            Some(SignedBodyScheme::HttpMessageSignature)
        );
    }

    /// A component's own parameter value is not a covered component:
    /// `"@query-param";name="content-digest"` signs a query parameter that
    /// happens to be called `content-digest`, not the body.
    #[test]
    fn message_signature_component_param_value_is_not_a_covered_component() {
        assert_eq!(
            scheme(
                &[
                    (
                        "signature-input",
                        r#"sig1=("@method" "@query-param";name="content-digest")"#
                    ),
                    ("signature", "sig1=:abc:")
                ],
                "https://api.example.com/v1?content-digest=x"
            ),
            None
        );
    }

    /// Guard against over-tightening the rule above: a real `"content-digest"`
    /// component alongside such a parameter is still detected.
    #[test]
    fn message_signature_component_after_a_param_value_is_still_detected() {
        assert_eq!(
            scheme(
                &[
                    (
                        "signature-input",
                        r#"sig1=("@query-param";name="content-digest" "content-digest")"#
                    ),
                    ("signature", "sig1=:abc:")
                ],
                "https://api.example.com/v1?content-digest=x"
            ),
            Some(SignedBodyScheme::HttpMessageSignature)
        );
    }

    /// A parenthesised decoy hiding inside a quoted parameter value must not
    /// be mistaken for the covered-component list either.
    #[test]
    fn message_signature_parenthesized_decoy_in_param_value_does_not_count() {
        assert_eq!(
            scheme(
                &[
                    (
                        "signature-input",
                        r#"sig1=("@method");tag="(\"content-digest\")""#
                    ),
                    ("signature", "sig1=:abc:")
                ],
                "https://api.example.com/v1"
            ),
            None
        );
    }

    /// The defect this label-matching fix closes: `sig2` names
    /// `content-digest`, but only `sig1` is actually signed. Without matching
    /// labels, this would be misclassified as body-signed even though the
    /// member that covers the digest was never signed.
    #[test]
    fn message_signature_content_digest_label_not_signed_is_not_detected() {
        assert_eq!(
            scheme(
                &[
                    (
                        "signature-input",
                        r#"sig1=("@method"), sig2=("@method" "content-digest")"#
                    ),
                    ("signature", "sig1=:abc:")
                ],
                "https://api.example.com/v1"
            ),
            None
        );
    }

    /// Same component lists, but this time the label that names
    /// `content-digest` (`sig2`) is the one actually signed — detected.
    #[test]
    fn message_signature_content_digest_label_signed_is_detected() {
        assert_eq!(
            scheme(
                &[
                    (
                        "signature-input",
                        r#"sig1=("@method"), sig2=("@method" "content-digest")"#
                    ),
                    ("signature", "sig2=:abc:")
                ],
                "https://api.example.com/v1"
            ),
            Some(SignedBodyScheme::HttpMessageSignature)
        );
    }

    /// The digest-covering label just needs to appear somewhere in
    /// `Signature`'s member list, not be the only one signed.
    #[test]
    fn message_signature_content_digest_label_signed_among_others_is_detected() {
        assert_eq!(
            scheme(
                &[
                    (
                        "signature-input",
                        r#"sig1=("@method"), sig2=("@method" "content-digest")"#
                    ),
                    ("signature", "sig1=:abc:, sig2=:def:")
                ],
                "https://api.example.com/v1"
            ),
            Some(SignedBodyScheme::HttpMessageSignature)
        );
    }

    /// Regression guard for the ordinary single-member case: the covering
    /// label is the only label and it is signed.
    #[test]
    fn message_signature_single_member_label_match_is_detected() {
        assert_eq!(
            scheme(
                &[
                    ("signature-input", r#"sig1=("@method" "content-digest")"#),
                    ("signature", "sig1=:abc:")
                ],
                "https://api.example.com/v1"
            ),
            Some(SignedBodyScheme::HttpMessageSignature)
        );
    }

    /// Every validator the rewrite path strips binds the body, so a signature
    /// covering any of them is body-signed. Missing one means redaction strips
    /// the header the signature covers and the upstream rejects the request
    /// opaquely — the exact failure this module prevents.
    ///
    /// Iterates [`BODY_DIGEST_HEADERS`] rather than restating it: a header
    /// added to the constant gains coverage here automatically, which is the
    /// point of there being one constant.
    #[test]
    fn cavage_signature_over_any_body_digest_header_is_detected() {
        for header_name in BODY_DIGEST_HEADERS {
            let name = header_name.as_str();
            let header = format!(
                r#"keyId="k",algorithm="hs2019",headers="(request-target) date {name}",signature="abc""#
            );
            assert_eq!(
                scheme(
                    &[("signature", header.as_str())],
                    "https://api.example.com/v1"
                ),
                Some(SignedBodyScheme::CavageSignature),
                "cavage signature over {name} should be body-signed"
            );
        }
    }

    /// The same set applies to RFC 9421 covered components, and is likewise
    /// read from the constant.
    #[test]
    fn message_signature_over_any_body_digest_component_is_detected() {
        for header_name in BODY_DIGEST_HEADERS {
            let name = header_name.as_str();
            let input = format!(r#"sig1=("@method" "{name}")"#);
            assert_eq!(
                scheme(
                    &[
                        ("signature-input", input.as_str()),
                        ("signature", "sig1=:abc:")
                    ],
                    "https://api.example.com/v1"
                ),
                Some(SignedBodyScheme::HttpMessageSignature),
                "message signature over {name} should be body-signed"
            );
        }
    }

    #[test]
    fn cavage_signature_needs_a_digest_component() {
        assert_eq!(
            scheme(
                &[(
                    "signature",
                    r#"keyId="k",algorithm="hs2019",headers="(request-target) date digest",signature="abc""#
                )],
                "https://api.example.com/v1"
            ),
            Some(SignedBodyScheme::CavageSignature)
        );
        assert_eq!(
            scheme(
                &[(
                    "signature",
                    r#"keyId="k",algorithm="hs2019",headers="(request-target) date",signature="abc""#
                )],
                "https://api.example.com/v1"
            ),
            None
        );
    }

    #[test]
    fn cavage_signature_carried_in_authorization_is_detected() {
        assert_eq!(
            scheme(
                &[(
                    "authorization",
                    r#"Signature keyId="k",algorithm="hs2019",headers="(request-target) digest",signature="abc""#
                )],
                "https://api.example.com/v1"
            ),
            Some(SignedBodyScheme::CavageSignature)
        );
    }

    /// A `keyId` that merely contains the substring `headers` must not shadow
    /// the real parameter — missing it would redact a signed body.
    #[test]
    fn cavage_headers_param_is_found_past_a_keyid_containing_its_name() {
        assert_eq!(
            scheme(
                &[(
                    "signature",
                    r#"keyId="webhook-headers-key",headers="(request-target) digest",signature="abc""#
                )],
                "https://api.example.com/v1"
            ),
            Some(SignedBodyScheme::CavageSignature)
        );
    }

    /// A decoy `headers="…"` crafted inside another parameter's quoted value
    /// must not shadow the genuine parameter either.
    #[test]
    fn cavage_decoy_headers_param_does_not_shadow_the_real_one() {
        assert_eq!(
            scheme(
                &[(
                    "signature",
                    r#"keyId="x,headers="host"",headers="(request-target) digest",signature="abc""#
                )],
                "https://api.example.com/v1"
            ),
            Some(SignedBodyScheme::CavageSignature)
        );
    }

    /// A comma inside a quoted parameter value must not be mistaken for a
    /// top-level auth-param boundary — here `keyId`'s quoted value contains
    /// `,headers = "digest"`, but there is no genuine top-level `headers`
    /// parameter.
    #[test]
    fn cavage_comma_inside_quoted_value_is_not_a_param_boundary() {
        assert_eq!(
            scheme(
                &[("signature", r#"keyId="x,headers = "digest"""#)],
                "https://api.example.com/v1"
            ),
            None
        );
    }

    #[test]
    fn cavage_headers_param_tolerates_whitespace_around_equals() {
        assert_eq!(
            scheme(
                &[(
                    "signature",
                    r#"keyId="k",algorithm="hs2019",headers = "(request-target) digest",signature="abc""#
                )],
                "https://api.example.com/v1"
            ),
            Some(SignedBodyScheme::CavageSignature)
        );
    }

    #[test]
    fn bearer_token_with_a_content_digest_does_not_sign_the_body() {
        assert_eq!(
            scheme(
                &[
                    ("authorization", "Bearer sk-live-token"),
                    ("content-digest", "sha-256=:stale:"),
                    ("content-md5", "stale"),
                ],
                "https://api.example.com/v1"
            ),
            None
        );
    }

    /// The gap #83 closes: `UNSIGNED-PAYLOAD` leaves the body redactable, but
    /// an AWS SDK upload signs `content-length` — which the rewrite must
    /// re-frame — so the request is broken by redaction anyway.
    #[test]
    fn sigv4_signed_headers_list_covers_the_framing_headers_it_names() {
        let headers = [
            (
                "authorization",
                "AWS4-HMAC-SHA256 Credential=AKIA/20260907/us-east-1/s3/aws4_request, \
                 SignedHeaders=content-length;host;x-amz-date, Signature=abc",
            ),
            ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
        ];
        let uri = "https://s3.amazonaws.com/b/k";
        assert_eq!(scheme(&headers, uri), None, "body should not be signed");
        assert_eq!(signed_framing(&headers, uri), ["content-length"]);
    }

    /// A `SignedHeaders` list that names none of them leaves redaction free to
    /// re-frame the body — the common `SignedHeaders=host;x-amz-date` upload.
    #[test]
    fn sigv4_signed_headers_list_that_names_no_framing_header_signs_none() {
        let headers = [
            (
                "authorization",
                "AWS4-HMAC-SHA256 Credential=AKIA/20260907/us-east-1/s3/aws4_request, \
                 SignedHeaders=host;x-amz-date, Signature=abc",
            ),
            ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
        ];
        let uri = "https://s3.amazonaws.com/b/k";
        assert!(signed_framing(&headers, uri).is_empty());
    }

    /// A presigned URL carries the list in the query string, where the `;`
    /// separators are percent-encoded.
    #[test]
    fn presigned_sigv4_signed_headers_query_param_is_separator_decoded() {
        assert_eq!(
            signed_framing(
                &[("x-amz-content-sha256", "UNSIGNED-PAYLOAD")],
                "https://s3.amazonaws.com/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256\
                 &X-Amz-SignedHeaders=content-encoding%3Bhost&X-Amz-Signature=abc"
            ),
            ["content-encoding"]
        );
    }

    /// RFC 9421: a component list naming a framing header counts only under a
    /// label `Signature` actually carries, exactly as the body-digest reading
    /// does — the two share one scan.
    #[test]
    fn message_signature_covers_a_framing_component_only_under_a_signed_label() {
        let uri = "https://api.example.com/v1";
        assert_eq!(
            signed_framing(
                &[
                    (
                        "signature-input",
                        r#"sig1=("@method" "content-length");created=1"#
                    ),
                    ("signature", "sig1=:abc:")
                ],
                uri
            ),
            ["content-length"]
        );
        assert!(
            signed_framing(
                &[
                    (
                        "signature-input",
                        r#"sig1=("@method" "content-length");created=1"#
                    ),
                    ("signature", "sig2=:abc:")
                ],
                uri
            )
            .is_empty(),
            "a component list under an unsigned label covers nothing"
        );
    }

    /// draft-cavage lists its covered headers space-separated in `headers="…"`.
    #[test]
    fn cavage_headers_param_covers_the_framing_headers_it_names() {
        assert_eq!(
            signed_framing(
                &[(
                    "signature",
                    r#"keyId="k",headers="(request-target) host content-length content-encoding",signature="abc""#
                )],
                "https://api.example.com/v1"
            ),
            ["content-length", "content-encoding"]
        );
    }

    /// draft-cavage and RFC 9421 both cover `transfer-encoding` like any other
    /// header the rewrite drops.
    #[test]
    fn a_signed_transfer_encoding_is_covered_like_the_other_framing_headers() {
        let headers = [
            (
                "authorization",
                "AWS4-HMAC-SHA256 Credential=AKIA/20260907/us-east-1/s3/aws4_request, \
                 SignedHeaders=host;transfer-encoding;x-amz-date, Signature=abc",
            ),
            ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
        ];
        assert_eq!(
            signed_framing(&headers, "https://s3.amazonaws.com/b/k"),
            ["transfer-encoding"]
        );
    }

    /// Bearer-token traffic signs nothing, so redaction re-frames it freely —
    /// the same over-inclusion trap [`body_signature_scheme`] avoids.
    #[test]
    fn bearer_token_request_signs_no_framing_headers() {
        assert!(
            signed_framing(
                &[
                    ("authorization", "Bearer sk-live-token"),
                    ("content-length", "42"),
                ],
                "https://api.example.com/v1"
            )
            .is_empty()
        );
    }

    /// `X-Amz-SignedHeaders` is a bare query parameter, so an unsigned request
    /// can carry one. Honoring it without SigV4 evidence would earn a spurious
    /// 403 under `block` and forward the body unredacted under `forward`.
    #[test]
    fn signed_headers_query_param_without_sigv4_evidence_signs_nothing() {
        assert!(
            signed_framing(
                &[("authorization", "Bearer sk-live-token")],
                "https://api.example.com/v1?X-Amz-SignedHeaders=content-length"
            )
            .is_empty(),
            "a query parameter alone is not a signature"
        );
        assert!(
            signed_framing(
                &[],
                "https://api.example.com/v1?X-Amz-SignedHeaders=content-length"
            )
            .is_empty(),
            "nor is it one on an unauthenticated request"
        );
    }
}
