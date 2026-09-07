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
    /// RFC 9421 HTTP Message Signatures covering a `content-digest` component.
    HttpMessageSignature,
    /// Legacy draft-cavage `Signature` covering a `digest` header.
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
            Self::HttpMessageSignature => "an RFC 9421 message signature over its content-digest",
            Self::CavageSignature => "a draft-cavage signature over its digest",
        }
    }
}

/// Which body-covering signature scheme authenticates this request, if any.
pub fn body_signature_scheme(headers: &HeaderMap, uri: &Uri) -> Option<SignedBodyScheme> {
    if aws_sigv4_signs_body(headers, uri) {
        return Some(SignedBodyScheme::AwsSigV4);
    }
    if message_signature_covers_content_digest(headers) {
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

/// RFC 9421: the signature covers the body only when a `Signature-Input`
/// component list names `"content-digest"` *and* a `Signature` header is also
/// present. RFC 9421 requires both fields — a request carrying only
/// `Signature-Input` is not signed at all. `Signature-Input` is a dictionary
/// field that may legally repeat across multiple field values, so every value
/// is scanned rather than only the first.
fn message_signature_covers_content_digest(headers: &HeaderMap) -> bool {
    if !header_present(headers, &SIGNATURE) {
        return false;
    }
    header_values(headers, &SIGNATURE_INPUT).any(signature_input_lists_content_digest)
}

/// RFC 9421: whether the request carries a `Signature-Input` + `Signature`
/// pair at all, regardless of which components the list names. Any such pair
/// signs the headers named in its component list — covering headers is the
/// whole point of the scheme — so this is broader than
/// [`message_signature_covers_content_digest`], which only cares about the
/// body.
fn message_signature_present(headers: &HeaderMap) -> bool {
    header_present(headers, &SIGNATURE) && header_present(headers, &SIGNATURE_INPUT)
}

/// Whether the parenthesised component list of a `Signature-Input` member —
/// not the member's other `;param=value` metadata — names the quoted
/// component `"content-digest"`.
///
/// A single-pass, quote-aware scan: paren depth is tracked only outside a
/// quoted string, since a `(` or `)` inside a quoted parameter value (e.g. a
/// `tag` crafted to contain `("content-digest")`) is not a real group
/// delimiter. Backslash escapes inside quoted strings are honored so an
/// escaped quote doesn't end the string early. Only a quoted string that
/// closes while depth >= 1 — i.e. genuinely inside the `(...)` component
/// list — is compared against `content-digest`.
fn signature_input_lists_content_digest(value: &str) -> bool {
    let mut depth: u32 = 0;
    let mut in_quote = false;
    let mut escaped = false;
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
                if depth >= 1 && current.eq_ignore_ascii_case("content-digest") {
                    return true;
                }
                current.clear();
            } else {
                current.push(ch);
            }
        } else {
            match ch {
                '"' => in_quote = true,
                '(' => depth += 1,
                ')' => depth = depth.saturating_sub(1),
                _ => {}
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
    candidates.flat_map(cavage_headers_params).any(|covered| {
        covered
            .split_whitespace()
            .any(|component| component == "digest" || component == "content-digest")
    })
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

/// Split `value` into its top-level, comma-separated auth-params, only
/// splitting on a `,` that sits outside a double-quoted parameter value.
///
/// A naive `str::split(',')` lets a decoy segment hide inside another
/// parameter's quoted value — e.g. a `keyId` crafted as
/// `"x,headers=\"host\""` — and get mistaken for a genuine top-level
/// `headers` parameter. This single-pass scan tracks quote state (with
/// backslash-escape handling, so an escaped quote doesn't end the string
/// early) and only treats a comma as a boundary while outside a quoted
/// string.
fn split_top_level_params(value: &str) -> impl Iterator<Item = &str> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut in_quote = false;
    let mut escaped = false;
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
                ',' => {
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
        map.insert(SIGNATURE, header::HeaderValue::from_static("sig1=:abc:"));
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
