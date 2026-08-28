//! How strongly `honmoon run` can hold a child to policy.
//!
//! `run` points the child at the ephemeral proxy with `http_proxy` and its five
//! spellings. Nothing makes the child read them: a binary with its own dialer, or
//! `curl --noproxy '*'`, reaches the network directly and never meets a verdict.
//! That is **TD-003**, and it is the gap between "firewall" and "suggestion".
//!
//! Closing it needs the operating system to delete the alternative rather than the
//! child to decline it — a namespace with no network at all on Linux, a Seatbelt
//! profile on macOS, and honmoon's proxy bridged in over a Unix socket. That work
//! is tracked in
//! [ADR-0005](../../../.please/docs/decisions/0005-empty-namespace-and-bridged-proxy-sockets.md)
//! and is not yet implemented, so every platform reports [`Isolation::Advisory`]
//! today.
//!
//! This module exists so the weakness is *stated* rather than silent. A user who
//! believes `honmoon run` is enforcing, when it is advisory, is worse off than one
//! who knows.

/// How much of the policy the wrapped child is actually held to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Isolation {
    /// The child has no network route that avoids the proxy.
    #[allow(dead_code)] // Produced once the ADR-0005 isolation paths land.
    Enforced,
    /// Only the proxy environment variables were set. A child that ignores them
    /// bypasses policy entirely. `reason` says why enforcement was unavailable.
    Advisory { reason: String },
}

impl Isolation {
    /// Decide what this host can offer for a child about to be spawned.
    pub fn probe() -> Self {
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

#[cfg(target_os = "linux")]
fn unavailable_reason() -> &'static str {
    "namespace isolation is not implemented yet (ADR-0005)"
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
        let warning = Isolation::probe()
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
    fn probe_explains_why_this_host_cannot_enforce() {
        let Isolation::Advisory { reason } = Isolation::probe() else {
            panic!("no platform enforces yet; see ADR-0005");
        };
        assert!(
            !reason.is_empty(),
            "an unexplained downgrade is not actionable"
        );
    }
}
