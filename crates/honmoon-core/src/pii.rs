//! Tier-1 deterministic PII detection: regex + checksum/format validation.
//!
//! Content-aware DLP for the data plane (roadmap Phase 5). Unlike the protocol
//! parsers, this scans decrypted request/response *bodies* for personal data.
//! Tier-1 covers only **deterministic** labels — those a checksum, Luhn, or a
//! strong structural rule can confirm — so false positives (which would block
//! legitimate traffic) stay near zero. Quasi-identifiers (PERSON, ADDRESS, …)
//! and keyword-anchored labels (ACCOUNT, passport, …) are out of scope here.
//!
//! The summary is exposed to CEL rules as the `pii` variable, e.g.
//! `pii.count > 0 && pii.max_severity >= 3`.
//!
//! Labels and severities mirror `datasets/pii/labels.yaml`; see
//! `docs/pii-benchmark-goals.md` for the evaluation contract.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// PII detection summary exposed to CEL as the `pii` variable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PiiFacts {
    /// Sorted, unique canonical labels found, e.g. `["EMAIL", "RRN"]`.
    pub types: Vec<String>,
    /// Total number of confirmed PII spans (a label may repeat).
    pub count: i64,
    /// Highest severity among findings: 3 high / 2 medium / 1 low / 0 none.
    pub max_severity: i64,
}

// Severity scale (mirrors labels.yaml high/medium/low).
const SEV_HIGH: i64 = 3;
const SEV_MEDIUM: i64 = 2;
const SEV_LOW: i64 = 1;

struct Detector {
    /// Canonical label (matches `datasets/pii/labels.yaml`).
    label: &'static str,
    severity: i64,
    /// Candidate matcher. `regex` has no look-around, so candidates are bounded
    /// by `\b` and disambiguated by `validate`.
    re: &'static LazyLock<Regex>,
    /// Confirms a candidate (checksum / Luhn / octet range / position). Keeps
    /// precision high; a candidate that fails is not counted.
    validate: fn(&str) -> bool,
}

// Candidate matchers. Kept deliberately permissive — `validate` is the gate.
static RRN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{6}-?\d{7}\b").unwrap());
static FRN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{6}-?\d{7}\b").unwrap());
static BRN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{3}-?\d{2}-?\d{5}\b").unwrap());
static CARD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,7}\b").unwrap());
static EMAIL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap());
static IPV4_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());
static PHONE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b0\d{1,2}-\d{3,4}-\d{4}\b|\b01[0-9]\d{7,8}\b").unwrap());

// Order matters only for readability; detection is order-independent.
static DETECTORS: &[Detector] = &[
    Detector {
        label: "RRN",
        severity: SEV_HIGH,
        re: &RRN_RE,
        validate: is_valid_rrn,
    },
    Detector {
        label: "FRN",
        severity: SEV_HIGH,
        re: &FRN_RE,
        validate: is_valid_frn,
    },
    Detector {
        label: "BUSINESS_REG_NO",
        severity: SEV_HIGH,
        re: &BRN_RE,
        validate: is_valid_brn,
    },
    Detector {
        label: "CREDIT_CARD",
        severity: SEV_HIGH,
        re: &CARD_RE,
        validate: is_luhn_valid,
    },
    Detector {
        label: "EMAIL",
        severity: SEV_MEDIUM,
        re: &EMAIL_RE,
        validate: always,
    },
    Detector {
        label: "IP",
        severity: SEV_LOW,
        re: &IPV4_RE,
        validate: is_valid_ipv4,
    },
    Detector {
        label: "PHONE",
        severity: SEV_MEDIUM,
        re: &PHONE_RE,
        validate: is_valid_phone,
    },
];

/// Scan `payload` for Tier-1 PII. Returns `None` when nothing is found, mirroring
/// the `Option<…Facts>` convention of the protocol parsers.
pub fn detect_pii(payload: &str) -> Option<PiiFacts> {
    let mut labels = BTreeSet::new();
    let mut count = 0i64;
    let mut max_severity = 0i64;

    for det in DETECTORS {
        for m in det.re.find_iter(payload) {
            if (det.validate)(m.as_str()) {
                labels.insert(det.label.to_string());
                count += 1;
                max_severity = max_severity.max(det.severity);
            }
        }
    }

    if count == 0 {
        return None;
    }
    Some(PiiFacts {
        types: labels.into_iter().collect(),
        count,
        max_severity,
    })
}

/// Extract ASCII digits from a candidate (drops hyphens/spaces).
fn digits(s: &str) -> Vec<u8> {
    s.bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| b - b'0')
        .collect()
}

fn always(_: &str) -> bool {
    true
}

// Calendar-plausible YYMMDD prefix (century-agnostic). Rejects impossible dates
// like month 13, so a checksum/position match on a random numeric id is not
// promoted to a high-severity finding that could deny clean traffic.
fn valid_yymmdd(d: &[u8]) -> bool {
    let month = d[2] * 10 + d[3];
    let day = d[4] * 10 + d[5];
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => 29, // century-agnostic: allow Feb 29
        _ => return false,
    };
    (1..=days_in_month).contains(&day)
}

// 주민등록번호: 13 digits, valid YYMMDD, gender digit (7th) 1–4, mod-11 checksum.
fn is_valid_rrn(s: &str) -> bool {
    let d = digits(s);
    d.len() == 13 && valid_yymmdd(&d) && matches!(d[6], 1..=4) && rrn_checksum_ok(&d)
}

// 외국인등록번호: 13 digits, valid YYMMDD, gender digit (7th) 5–8. Post-2020
// issuances dropped the check digit, so we gate on the date + position rather
// than a checksum (a strict checksum would miss every modern FRN). The optional
// hyphen in FRN_RE also lets unhyphenated FRNs be caught, which RRN's validator
// rejects (its position digit is 1–4).
fn is_valid_frn(s: &str) -> bool {
    let d = digits(s);
    d.len() == 13 && valid_yymmdd(&d) && matches!(d[6], 5..=8)
}

fn rrn_checksum_ok(d: &[u8]) -> bool {
    const W: [u32; 12] = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
    let sum: u32 = d[..12].iter().zip(W).map(|(&x, w)| u32::from(x) * w).sum();
    let check = (11 - (sum % 11)) % 10;
    u32::from(d[12]) == check
}

// 사업자등록번호: 10 digits, mod-10 checksum with weights [1,3,7,1,3,7,1,3,5]
// plus the carry from the 9th digit × 5.
fn is_valid_brn(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 10 {
        return false;
    }
    const W: [u32; 9] = [1, 3, 7, 1, 3, 7, 1, 3, 5];
    let mut sum: u32 = d[..9].iter().zip(W).map(|(&x, w)| u32::from(x) * w).sum();
    sum += (u32::from(d[8]) * 5) / 10;
    let check = (10 - (sum % 10)) % 10;
    u32::from(d[9]) == check
}

// Credit card: Luhn over 13–19 digits. A 13-digit Korean id (RRN/FRN) can pass
// Luhn by coincidence (~1 in 10); exclude those so it is not double-counted as a card.
fn is_luhn_valid(s: &str) -> bool {
    let d = digits(s);
    if !(13..=19).contains(&d.len()) {
        return false;
    }
    if is_valid_rrn(s) || is_valid_frn(s) {
        return false;
    }
    let mut sum = 0u32;
    for (i, &x) in d.iter().rev().enumerate() {
        let mut v = u32::from(x);
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum % 10 == 0
}

// IPv4: four octets, each 0–255.
fn is_valid_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

// Korean phone: 9–11 digits whose prefix is a real mobile/landline/service code.
// Gating on the allowed prefix set (not just a leading 0) keeps a precision-first
// detector from flagging impossible numbers like `000-0000-0000`.
fn is_valid_phone(s: &str) -> bool {
    let d = digits(s);
    if !(9..=11).contains(&d.len()) {
        return false;
    }
    let ds: String = d.iter().map(|&x| char::from(b'0' + x)).collect();
    const PREFIXES: &[&str] = &[
        // mobile
        "010", "011", "016", "017", "018", "019", // Seoul + area codes
        "02", "031", "032", "033", "041", "042", "043", "044", "051", "052", "053", "054", "055",
        "061", "062", "063", "064", // service numbers (VoIP / toll-free / personal)
        "070", "080", "0303", "0505", "0506", "0507",
    ];
    PREFIXES.iter().any(|p| ds.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(s: &str) -> PiiFacts {
        detect_pii(s).expect("expected a detection")
    }

    #[test]
    fn detects_valid_rrn_via_checksum() {
        let f = facts("제 주민번호는 670125-1230644 입니다");
        assert_eq!(f.types, vec!["RRN"]);
        assert_eq!(f.count, 1);
        assert_eq!(f.max_severity, SEV_HIGH);
    }

    #[test]
    fn rejects_rrn_with_bad_checksum() {
        // Same number, last digit changed → checksum fails → not an RRN.
        assert!(detect_pii("670125-1230645").is_none());
    }

    #[test]
    fn rrn_works_without_hyphen() {
        assert_eq!(facts("6701251230644").types, vec!["RRN"]);
    }

    #[test]
    fn detects_frn_by_position_digit() {
        // 7th digit 7 → foreigner registration number.
        assert_eq!(facts("001026-7084708").types, vec!["FRN"]);
    }

    #[test]
    fn detects_frn_without_hyphen() {
        // Unhyphenated FRN must still be caught (not silently missed).
        assert_eq!(facts("0010267084708").types, vec!["FRN"]);
    }

    #[test]
    fn rejects_impossible_birthdate() {
        // Month 99 → not a real RRN/FRN even if position/checksum-shaped.
        assert!(!is_valid_frn("009913-5000000"));
        assert!(!is_valid_rrn("009913-1000004"));
    }

    #[test]
    fn rejects_all_zero_phone() {
        assert!(detect_pii("000-0000-0000").is_none());
    }

    #[test]
    fn valid_kr_id_is_not_also_a_card() {
        // A 13-digit RRN/FRN must never be double-counted as CREDIT_CARD.
        for s in ["6701251230644", "0010267084708"] {
            let t = facts(s).types;
            assert!(!t.contains(&"CREDIT_CARD".to_string()), "{s} → {t:?}");
        }
    }

    #[test]
    fn detects_credit_card_via_luhn() {
        let f = facts("card 4111-1111-1111-1111 on file");
        assert_eq!(f.types, vec!["CREDIT_CARD"]);
        assert_eq!(f.max_severity, SEV_HIGH);
    }

    #[test]
    fn rejects_luhn_invalid_card() {
        assert!(detect_pii("4111-1111-1111-1112").is_none());
    }

    #[test]
    fn detects_email_and_ip_and_phone() {
        let f = facts(r#"{"email":"a.b@naver.com","ip":"10.0.0.1","tel":"010-1234-5678"}"#);
        assert_eq!(f.types, vec!["EMAIL", "IP", "PHONE"]);
        assert_eq!(f.count, 3);
        assert_eq!(f.max_severity, SEV_MEDIUM); // email/phone medium, ip low
    }

    #[test]
    fn rejects_out_of_range_ipv4() {
        assert!(detect_pii("999.1.1.1").is_none());
    }

    #[test]
    fn detects_business_reg_no() {
        // 220-81-62517 is a valid BRN checksum.
        assert_eq!(
            facts("사업자번호 220-81-62517").types,
            vec!["BUSINESS_REG_NO"]
        );
    }

    #[test]
    fn hard_negatives_are_not_flagged() {
        // Order/tracking ids, UUIDs, git shas — must produce no findings.
        assert!(detect_pii("ORD-1234567890").is_none());
        assert!(detect_pii("3f9a1c2b4d5e6f708192a3b4c5d6e7f8").is_none());
    }

    #[test]
    fn counts_multiple_and_takes_max_severity() {
        let f = facts("670125-1230644 and a.b@x.io");
        assert_eq!(f.count, 2);
        assert_eq!(f.types, vec!["EMAIL", "RRN"]);
        assert_eq!(f.max_severity, SEV_HIGH);
    }
}
