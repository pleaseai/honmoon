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

/// SigV4 binds the body through the payload hash, unless the request opted out
/// of payload signing with `UNSIGNED-PAYLOAD` / `STREAMING-UNSIGNED-PAYLOAD…`.
fn aws_sigv4_signs_body(headers: &HeaderMap, uri: &Uri) -> bool {
    let payload_hash = header_str(headers, &X_AMZ_CONTENT_SHA256);
    if let Some(hash) = payload_hash {
        if hash.eq_ignore_ascii_case("UNSIGNED-PAYLOAD")
            || starts_with_ignore_ascii_case(hash, "STREAMING-UNSIGNED-PAYLOAD")
        {
            return false;
        }
    }
    // A hex payload hash binds the body on its own — the signature that covers
    // it may live in a scheme we do not otherwise recognize.
    let hex_payload_hash = payload_hash
        .is_some_and(|hash| !hash.is_empty() && hash.bytes().all(|b| b.is_ascii_hexdigit()));

    aws_sigv4_authenticates(headers, uri) || hex_payload_hash
}

/// Whether the request carries SigV4 authentication at all — header-signed
/// or presigned — irrespective of whether the payload itself is signed.
fn aws_sigv4_authenticates(headers: &HeaderMap, uri: &Uri) -> bool {
    let signed_authorization = header_str(headers, &header::AUTHORIZATION).is_some_and(|value| {
        starts_with_ignore_ascii_case(value, "AWS4-HMAC-SHA256")
            || starts_with_ignore_ascii_case(value, "AWS4-ECDSA-P256-SHA256")
    });
    // A presigned URL carries the algorithm in the query string instead.
    let presigned = uri.query().is_some_and(|query| {
        query.split('&').any(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            name.eq_ignore_ascii_case("X-Amz-Algorithm")
                && starts_with_ignore_ascii_case(value, "AWS4-")
        })
    });
    signed_authorization || presigned
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
    let signed_labels: HashSet<String> = header_values(headers, &SIGNATURE)
        .flat_map(signature_member_labels)
        .collect();
    if signed_labels.is_empty() {
        return false;
    }
    header_values(headers, &SIGNATURE_INPUT)
        .flat_map(signature_input_body_digest_labels)
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
/// field value whose parenthesised component list names a body digest.
///
/// A member is `label=value`, members separated by a top-level comma (see
/// [`split_top_level_params`]). The label is the token before the member's
/// first `=`, trimmed of whitespace. Labels are normalized to lowercase for
/// the comparison in [`message_signature_covers_body_digest`] — dictionary
/// keys are case-sensitive tokens per Structured Fields, but signature labels
/// are lowercase in practice, and both sides of that comparison are
/// normalized identically, so this cannot turn a mismatch into a false match.
fn signature_input_body_digest_labels(value: &str) -> impl Iterator<Item = String> + '_ {
    split_top_level_params(value).filter_map(|member| {
        let (label, rest) = member.split_once('=')?;
        let label = label.trim();
        if label.is_empty() || !signature_input_lists_body_digest(rest) {
            return None;
        }
        Some(label.to_ascii_lowercase())
    })
}

/// The dictionary-member labels present in a `Signature` field value, e.g.
/// `sig1` and `sig2` in `sig1=:abc:, sig2=:def:`. Normalized to lowercase to
/// match [`signature_input_body_digest_labels`].
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
/// covering the payload itself: the digest cannot survive a rewrite, and
/// `forwarded_request` strips all four as stale validators, so the signature
/// is broken outright rather than merely mismatched.
///
/// **Keep this in sync with the validators `forwarded_request` strips.** A
/// name stripped there but missing here is a signed request this module fails
/// to detect — which is precisely the opaque upstream rejection the module
/// exists to prevent.
const BODY_DIGEST_HEADERS: [&str; 4] = ["digest", "content-digest", "content-md5", "repr-digest"];

fn is_body_digest_header(name: &str) -> bool {
    BODY_DIGEST_HEADERS
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

/// Whether the parenthesised component list of a `Signature-Input` member —
/// not the member's other `;param=value` metadata — names a quoted component
/// that is one of [`BODY_DIGEST_HEADERS`].
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
fn signature_input_lists_body_digest(value: &str) -> bool {
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
                if depth >= 1 && !is_param_value && is_body_digest_header(&current) {
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
    let candidates = header_values(headers, &SIGNATURE)
        .chain(header_values(headers, &header::AUTHORIZATION).filter_map(strip_signature_scheme));
    candidates
        .flat_map(cavage_headers_params)
        .any(|covered| covered.split_whitespace().any(is_body_digest_header))
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

    #[test]
    fn presigned_sigv4_query_signs_the_body() {
        assert_eq!(
            scheme(
                &[],
                "https://s3.amazonaws.com/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=60"
            ),
            Some(SignedBodyScheme::AwsSigV4)
        );
    }

    #[test]
    fn bare_hex_payload_hash_signs_the_body() {
        assert_eq!(
            scheme(
                &[("x-amz-content-sha256", &"a".repeat(64))],
                "https://s3.amazonaws.com/b/k"
            ),
            Some(SignedBodyScheme::AwsSigV4)
        );
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

    /// Every validator `forwarded_request` strips binds the body, so a
    /// signature covering any of them is body-signed. Missing one means
    /// redaction strips the header the signature covers and the upstream
    /// rejects the request opaquely — the exact failure this module prevents.
    #[test]
    fn cavage_signature_over_any_body_digest_header_is_detected() {
        for name in ["digest", "content-digest", "content-md5", "repr-digest"] {
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

    /// The same set applies to RFC 9421 covered components.
    #[test]
    fn message_signature_over_any_body_digest_component_is_detected() {
        for name in ["digest", "content-digest", "content-md5", "repr-digest"] {
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
}
