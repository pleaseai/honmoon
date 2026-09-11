//! Salt derivation shared by both Claude Code hook transports.
//!
//! Placeholder minting is `HMAC(salt, secret)`, so a secret only tokenizes to
//! the same placeholder in two places when both places key the HMAC with the
//! same salt. A session can mix transports — the plugin's command hooks run
//! `honmoon hook` while its function-hook module can POST to the management
//! endpoint — and byte-stable placeholders across a session are what keeps a
//! provider's prompt-cache prefix intact from turn to turn. Both transports
//! therefore derive their salt here, from the same two inputs (#98):
//!
//! - the **machine key**: the random secret persisted at `~/.honmoon/hook-salt`,
//!   which makes a placeholder unforgeable without local access, and
//! - the **salt context**: an operator-pinned context if there is one, else the
//!   hook payload's own `session_id` (see [`hook_salt_context`]).
//!
//! Neither input is this crate's to fetch: reading the machine key is
//! filesystem I/O the transports own, which keeps `honmoon-core` I/O-free.

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Derive the HMAC salt that keys placeholder minting for one hook session.
///
/// Deterministic in both inputs: the same machine key and context always yield
/// the same salt, so two transports that agree on the context mint identical
/// placeholders for a given secret.
pub fn derive_hook_salt(machine_key: &[u8], salt_context: &str) -> Vec<u8> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(machine_key).expect("HMAC accepts a key of any length");
    mac.update(salt_context.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Resolve the salt context for one hook payload.
///
/// A `pinned` context wins — `honmoon hook --salt-context`,
/// `HONMOON_HOOK_SALT_CONTEXT`, or the gateway's `--hook-salt-context` — so an
/// operator can deliberately separate (or deliberately join) instances that
/// share one machine key. Otherwise the payload's `session_id` scopes the salt
/// to the session, which is what the plugin sends on every event over either
/// transport. A payload without a `session_id` and no pin falls back to the
/// empty context rather than to a random one: redaction stays deterministic,
/// and the machine key still keys the HMAC.
pub fn hook_salt_context<'a>(pinned: Option<&'a str>, payload: &'a Value) -> &'a str {
    pinned
        .or_else(|| payload.get("session_id").and_then(Value::as_str))
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"machine-key-for-tests";

    #[test]
    fn salt_is_deterministic_per_context_and_distinct_across_contexts() {
        assert_eq!(
            derive_hook_salt(KEY, "session-a"),
            derive_hook_salt(KEY, "session-a"),
            "the same context must re-derive the same salt"
        );
        assert_ne!(
            derive_hook_salt(KEY, "session-a"),
            derive_hook_salt(KEY, "session-b"),
            "distinct sessions must not share a salt"
        );
        assert_ne!(
            derive_hook_salt(KEY, "session-a"),
            derive_hook_salt(b"another-machine-key", "session-a"),
            "the machine key must key the derivation"
        );
    }

    #[test]
    fn context_prefers_a_pin_then_the_payload_session_id() {
        let payload = serde_json::json!({ "session_id": "sess-1" });
        assert_eq!(
            hook_salt_context(Some("pinned"), &payload),
            "pinned",
            "an operator-pinned context outranks the payload"
        );
        assert_eq!(
            hook_salt_context(None, &payload),
            "sess-1",
            "an unpinned transport keys on the session"
        );
        assert_eq!(
            hook_salt_context(None, &serde_json::json!({})),
            "",
            "a payload without a session id falls back to the empty context"
        );
    }
}
