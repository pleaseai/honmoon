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

/// SigV4 binds the body through the payload hash, unless the request opted out
/// of payload signing with `UNSIGNED-PAYLOAD` / `STREAMING-UNSIGNED-PAYLOAD…`.
fn aws_sigv4_signs_body(headers: &HeaderMap, uri: &Uri) -> bool {
    let payload_hash = header_str(headers, &X_AMZ_CONTENT_SHA256);
    if let Some(hash) = payload_hash
        && (hash.eq_ignore_ascii_case("UNSIGNED-PAYLOAD")
            || starts_with_ignore_ascii_case(hash, "STREAMING-UNSIGNED-PAYLOAD"))
    {
        return false;
    }

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
    // A hex payload hash binds the body on its own — the signature that covers
    // it may live in a scheme we do not otherwise recognize.
    let hex_payload_hash = payload_hash
        .is_some_and(|hash| !hash.is_empty() && hash.bytes().all(|b| b.is_ascii_hexdigit()));

    signed_authorization || presigned || hex_payload_hash
}

/// RFC 9421: the signature covers the body only when its component list names
/// `"content-digest"`.
fn message_signature_covers_content_digest(headers: &HeaderMap) -> bool {
    header_str(headers, &SIGNATURE_INPUT)
        .is_some_and(|value| value.to_ascii_lowercase().contains("\"content-digest\""))
}

/// draft-cavage: the signature covers the body only when its `headers="…"` list
/// names a body digest header.
fn cavage_signature_covers_digest(headers: &HeaderMap) -> bool {
    let Some(value) = header_str(headers, &SIGNATURE) else {
        return false;
    };
    let lowered = value.to_ascii_lowercase();
    let Some(rest) = lowered.split_once("headers=\"").map(|(_, rest)| rest) else {
        return false;
    };
    let Some((covered, _)) = rest.split_once('"') else {
        return false;
    };
    covered
        .split_whitespace()
        .any(|component| component == "digest" || component == "content-digest")
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
                &[(
                    "signature-input",
                    r#"sig1=("@method" "@authority" "content-digest");created=1618884473"#
                )],
                "https://api.example.com/v1"
            ),
            Some(SignedBodyScheme::HttpMessageSignature)
        );
        assert_eq!(
            scheme(
                &[(
                    "signature-input",
                    r#"sig1=("@method" "@authority");created=1618884473"#
                )],
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
