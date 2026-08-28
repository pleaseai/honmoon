//! How strongly `honmoon run` can hold a child to policy.
//!
//! `run` points the child at the ephemeral proxy with `http_proxy` and its five
//! spellings. Nothing makes the child read them: a binary with its own dialer, or
//! `curl --noproxy '*'`, reaches the network directly and never meets a verdict.
//! That is **TD-003**, and it is the gap between "firewall" and "suggestion".
//!
//! Closing it needs the operating system to delete the alternative rather than the
//! child to decline it — a namespace with no network at all on Linux, a Seatbelt
//! profile on macOS, and honmoon's proxy bridged in over a Unix socket, per
//! [ADR-0005](../../../.please/docs/decisions/0005-empty-namespace-and-bridged-proxy-sockets.md).
//! The Linux half is implemented in [`linux`]; macOS still reports
//! [`Isolation::Advisory`].
//!
//! This module exists so the weakness is *stated* rather than silent. A user who
//! believes `honmoon run` is enforcing, when it is advisory, is worse off than one
//! who knows.

// The pump is built on `std::os::unix` sockets and errno constants, so it only
// exists where those do. A non-Unix target compiles neither it nor `linux`
// below, and reaches the advisory fallback that `unavailable_reason` already
// spells out for platforms without an implementation.
#[cfg(unix)]
mod bridge;

#[cfg(target_os = "linux")]
pub mod linux;

/// How much of the policy the wrapped child is actually held to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Isolation {
    /// The child has no network route that avoids the proxy.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "only Linux can produce this today (ADR-0005)")
    )]
    Enforced,
    /// Only the proxy environment variables were set. A child that ignores them
    /// bypasses policy entirely. `reason` says why enforcement was unavailable.
    Advisory { reason: String },
}

impl Isolation {
    /// Decide what this host can offer for a child about to be spawned.
    pub fn probe() -> Self {
        #[cfg(target_os = "linux")]
        if linux::namespaces_available() {
            return Self::Enforced;
        }

        Self::Advisory {
            reason: unavailable_reason().to_string(),
        }
    }

    /// One line for the operator, or `None` when enforcement is real.
    ///
    /// Deliberately blunt: it names the bypass rather than hinting at it, because
    /// the failure mode is someone trusting the wrapper more than it deserves.
    pub fn warning(&self) -> Option<String> {
        match self {
            Self::Enforced => None,
            Self::Advisory { reason } => Some(format!(
                "egress policy is ADVISORY, not enforced: {reason}. \
                 A child that ignores the proxy environment variables reaches \
                 the network directly and is never evaluated against the policy."
            )),
        }
    }
}

/// The proxy variables handed to a wrapped child.
///
/// Six spellings because there is no single convention: curl reads the lowercase
/// forms, many Go and Java clients read the uppercase ones, and `all_proxy`
/// catches clients that route non-HTTP schemes through the same setting.
pub fn proxy_env(proxy_url: &str) -> [(&'static str, &str); 6] {
    [
        ("http_proxy", proxy_url),
        ("https_proxy", proxy_url),
        ("HTTP_PROXY", proxy_url),
        ("HTTPS_PROXY", proxy_url),
        ("all_proxy", proxy_url),
        ("ALL_PROXY", proxy_url),
    ]
}

#[cfg(target_os = "linux")]
fn unavailable_reason() -> &'static str {
    "Linux namespace isolation is unavailable on this host — a kernel or \
     container policy refused a required namespace"
}

#[cfg(target_os = "macos")]
fn unavailable_reason() -> &'static str {
    "Seatbelt isolation is not implemented yet (ADR-0005)"
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn unavailable_reason() -> &'static str {
    "enforced isolation has no design for this platform yet; ADR-0005 covers Linux and macOS"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisory_warning_names_the_bypass() {
        let warning = Isolation::Advisory {
            reason: "a stated reason".to_string(),
        }
        .warning()
        .expect("an advisory host must warn");
        assert!(
            warning.contains("ADVISORY"),
            "the operator has to see the posture, got: {warning}"
        );
        assert!(
            warning.contains("ignores the proxy environment variables"),
            "the warning must name how policy is bypassed, got: {warning}"
        );
    }

    #[test]
    fn enforced_isolation_stays_quiet() {
        assert_eq!(
            Isolation::Enforced.warning(),
            None,
            "a warning on an enforcing host would train operators to ignore it"
        );
    }

    #[test]
    fn a_downgrade_always_explains_itself() {
        // What `probe()` returns now depends on the host — Linux with user
        // namespaces enforces, everything else does not — so the invariant worth
        // asserting is not *which* answer comes back, but that a downgrade never
        // arrives unexplained.
        if let Isolation::Advisory { reason } = Isolation::probe() {
            assert!(
                !reason.is_empty(),
                "an unexplained downgrade is not actionable"
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn platforms_without_an_implementation_stay_advisory() {
        assert!(
            matches!(Isolation::probe(), Isolation::Advisory { .. }),
            "only Linux implements enforcement today; claiming otherwise would be \
             the exact overstatement this module exists to prevent"
        );
    }

    #[test]
    fn proxy_env_covers_every_spelling_a_client_might_read() {
        let env = proxy_env("http://127.0.0.1:8080");
        for name in ["http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"] {
            assert!(
                env.iter().any(|(key, _)| *key == name),
                "{name} must be set — a client reading only that spelling would \
                 otherwise reach the network unproxied"
            );
        }
        assert!(
            env.iter()
                .all(|(_, value)| *value == "http://127.0.0.1:8080"),
            "every variable must point at the same proxy"
        );
    }
}
