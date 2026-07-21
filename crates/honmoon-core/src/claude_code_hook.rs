//! Shared Claude Code hook verdict logic.
//!
//! This module is transport-independent: both `honmoon hook` and the management
//! API feed it the unwrapped hook JSON payload and a session salt, and receive
//! the same JSON verdict. No-op and malformed/unknown payloads deliberately
//! produce `{}` so a hook integration never blocks normal work by accident.
//! Transport adapters preserve their channel conventions: the CLI emits empty
//! stdout for this no-op per #27, while HTTP returns the `{}` body with 200.

use serde_json::{Value, json};

use crate::secret_tokenizer::Mapping;
use crate::{DEFAULT_MIN_PII_SEVERITY, redact};

/// PII severity worth blocking a prompt over (HIGH: RRN, card, …).
const PII_SEVERITY_HIGH: i64 = 3;
/// Maximum JSON nesting depth scanned in tool output.
const MAX_REDACT_DEPTH: usize = 64;
/// Safe replacement for a subtree beyond [`MAX_REDACT_DEPTH`].
const DEPTH_LIMIT_MARKER: &str = "[honmoon: redacted — nesting exceeds scan depth]";

/// A Claude Code hook verdict and the reversible substitutions it introduced.
///
/// The mapping is intentionally not serializable or printable. The CLI drops it
/// when its one-shot process exits; the management API records it in the live
/// mapping store shared with the proxy wire-redaction path, so either transport's
/// placeholders can be restored on responses within the same gateway process.
pub struct ClaudeCodeHookVerdict {
    output: Value,
    mapping: Mapping,
}

impl ClaudeCodeHookVerdict {
    /// JSON body/stdout value required by the Claude Code hook protocol.
    pub fn output(&self) -> &Value {
        &self.output
    }

    /// Split the transport output from its secret-bearing reverse mapping.
    pub fn into_parts(self) -> (Value, Mapping) {
        (self.output, self.mapping)
    }
}

/// Outcome of a transport's best-effort filesystem resolution of the tool's
/// requested file path.
///
/// Symlink protection lives with the I/O-owning transports so `honmoon-core`
/// stays free of filesystem access: transports canonicalize the requested path
/// in the *agent's* filesystem context and report what they found. The variants
/// deliberately distinguish "resolved and clean" from "could not resolve at
/// all" — collapsing the two is what let an agent-relative symlink slip past
/// the HTTP transport's `PreToolUse` deny (issue #55).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathResolution {
    /// The canonicalized target matches [`is_sensitive_path`]: deny.
    Sensitive,
    /// The path resolved (or resolution is knowably moot, e.g. a not-yet-created
    /// file in the agent's own filesystem) and the target is not sensitive. The
    /// literal path check on the raw string still applies.
    NotSensitive,
    /// The transport could not resolve the path in the agent's filesystem
    /// context at all (e.g. the HTTP gateway received a relative path it cannot
    /// anchor to the agent's `cwd`). `PreToolUse` treats this conservatively —
    /// deny, surfacing that the check could not run — rather than silently
    /// evaluating to "not sensitive".
    Unresolved,
}

/// Evaluate one Claude Code hook payload.
///
/// `resolution` lets I/O-owning transports preserve symlink protection without
/// putting filesystem access in `honmoon-core`: transports resolve the
/// requested path best-effort and report a [`PathResolution`].
pub fn claude_code_hook_verdict(
    payload: &Value,
    salt: &[u8],
    resolution: PathResolution,
) -> ClaudeCodeHookVerdict {
    let (output, mapping) = match payload.get("hook_event_name").and_then(Value::as_str) {
        Some("PreToolUse") => (
            handle_pre_tool_use(payload, resolution).unwrap_or_else(noop),
            Mapping::new(),
        ),
        Some("PostToolUse") => {
            handle_post_tool_use(payload, salt).unwrap_or_else(|| (noop(), Mapping::new()))
        }
        Some("UserPromptSubmit") => (
            handle_user_prompt_submit(payload, salt).unwrap_or_else(noop),
            Mapping::new(),
        ),
        _ => (noop(), Mapping::new()),
    };
    ClaudeCodeHookVerdict { output, mapping }
}

fn noop() -> Value {
    json!({})
}

fn handle_pre_tool_use(payload: &Value, resolution: PathResolution) -> Option<Value> {
    let tool_name = payload.get("tool_name").and_then(Value::as_str)?;
    if !matches!(
        tool_name,
        "Read" | "Edit" | "Write" | "MultiEdit" | "NotebookEdit"
    ) {
        return None;
    }
    let file_path = payload
        .get("tool_input")
        .and_then(|input| {
            input
                .get("file_path")
                .or_else(|| input.get("notebook_path"))
        })
        .and_then(Value::as_str)?;
    if is_sensitive_path(file_path) || resolution == PathResolution::Sensitive {
        return Some(pre_tool_use_deny(format!(
            "honmoon: reading or modifying `{file_path}` is blocked — it matches a known-sensitive path (credentials or key material). If a specific value is genuinely needed, ask the user to provide just that value."
        )));
    }
    if resolution == PathResolution::Unresolved {
        // The symlink check could not run at all; denying is the conservative
        // choice, and the reason tells the agent how to make it pass (issue #55).
        return Some(pre_tool_use_deny(format!(
            "honmoon: access to `{file_path}` is blocked — the path could not be resolved against the agent's working directory, so the sensitive-path (symlink) check cannot run. Retry with an absolute path."
        )));
    }
    None
}

fn pre_tool_use_deny(reason: String) -> Value {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason
        }
    })
}

fn handle_post_tool_use(payload: &Value, salt: &[u8]) -> Option<(Value, Mapping)> {
    // Preserve the plugin's existing Bash/Grep protection in addition to the
    // issue's required Read event: those tools can surface the same file bytes.
    let tool_name = payload.get("tool_name").and_then(Value::as_str)?;
    if !matches!(tool_name, "Read" | "Bash" | "Grep") {
        return None;
    }
    let response = payload.get("tool_response")?;
    let (redacted, changed, mapping) = redact_json_value(response, salt);
    if !changed {
        return None;
    }
    Some((
        json!({
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "updatedToolOutput": redacted
            }
        }),
        mapping,
    ))
}

fn handle_user_prompt_submit(payload: &Value, salt: &[u8]) -> Option<Value> {
    let prompt = payload.get("prompt").and_then(Value::as_str)?;
    let outcome = redact(prompt, salt, PII_SEVERITY_HIGH);
    if !(outcome.has_secret() || outcome.max_pii_severity >= PII_SEVERITY_HIGH) {
        return None;
    }
    let kinds = outcome.labels().join(", ");
    Some(json!({
        "decision": "block",
        "reason": format!(
            "honmoon: your prompt appears to contain a secret or sensitive identifier ({kinds}). A prompt-submit hook cannot rewrite the prompt, so it was blocked. Remove the value (or reference it indirectly) and resubmit."
        )
    }))
}

fn redact_json_value(value: &Value, salt: &[u8]) -> (Value, bool, Mapping) {
    redact_json_value_at(value, salt, 0)
}

fn redact_json_value_at(value: &Value, salt: &[u8], depth: usize) -> (Value, bool, Mapping) {
    if depth >= MAX_REDACT_DEPTH {
        return (
            Value::String(DEPTH_LIMIT_MARKER.to_string()),
            true,
            Mapping::new(),
        );
    }
    match value {
        Value::String(text) => {
            let outcome = redact(text, salt, DEFAULT_MIN_PII_SEVERITY);
            (
                Value::String(outcome.text),
                outcome.redacted,
                outcome.mapping,
            )
        }
        Value::Array(items) => {
            let mut changed = false;
            let mut mapping = Mapping::new();
            let mut output = Vec::with_capacity(items.len());
            for item in items {
                let (redacted, item_changed, item_mapping) =
                    redact_json_value_at(item, salt, depth + 1);
                changed |= item_changed;
                mapping.extend(item_mapping);
                output.push(redacted);
            }
            (Value::Array(output), changed, mapping)
        }
        Value::Object(fields) => {
            let mut changed = false;
            let mut mapping = Mapping::new();
            let mut output = serde_json::Map::with_capacity(fields.len());
            for (key, value) in fields {
                let (redacted, value_changed, value_mapping) =
                    redact_json_value_at(value, salt, depth + 1);
                changed |= value_changed;
                mapping.extend(value_mapping);
                output.insert(key.clone(), redacted);
            }
            (Value::Object(output), changed, mapping)
        }
        other => (other.clone(), false, Mapping::new()),
    }
}

/// Whether a path names credential or private-key material.
///
/// Matching is case-insensitive and accepts both Unix and Windows separators.
/// Template/sample files and public SSH keys are intentionally allowed.
pub fn is_sensitive_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let base = lower.rsplit(['/', '\\']).next().unwrap_or(lower.as_str());

    const TEMPLATE_SUFFIXES: &[&str] = &[".example", ".sample", ".template", ".dist"];
    if TEMPLATE_SUFFIXES
        .iter()
        .any(|suffix| base.ends_with(suffix))
    {
        return false;
    }
    if base == ".env" || base == ".envrc" || base.starts_with(".env.") {
        return true;
    }
    const SENSITIVE_BASENAMES: &[&str] = &[
        ".git-credentials",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "credentials",
    ];
    // Private SSH keys ship as `id_<type>` plus renamed variants and backups
    // (`id_ed25519_old`, `id_ecdsa.bak`); only the `.pub` half is public. Match
    // every key type by prefix so variants of all four types are covered — not
    // just the exact `id_rsa` basename.
    const SSH_KEY_PREFIXES: &[&str] = &["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"];
    if SENSITIVE_BASENAMES.contains(&base)
        || (SSH_KEY_PREFIXES
            .iter()
            .any(|prefix| base.starts_with(prefix))
            && !base.ends_with(".pub"))
    {
        return true;
    }
    const SENSITIVE_EXTENSIONS: &[&str] =
        &[".pem", ".key", ".p12", ".pfx", ".keystore", ".jks", ".asc"];
    if SENSITIVE_EXTENSIONS
        .iter()
        .any(|extension| base.ends_with(extension))
    {
        return true;
    }
    // Match path fragments cross-platform: normalize Windows separators so
    // `…\.gnupg\secring.gpg` is caught like the Unix form, and use no leading
    // slash so relative paths (`cat .aws/credentials`) match too — this runs on
    // raw, un-canonicalized literal paths as well as canonicalized ones.
    const SENSITIVE_FRAGMENTS: &[&str] = &[".aws/credentials", ".gnupg/"];
    let normalized = lower.replace('\\', "/");
    SENSITIVE_FRAGMENTS
        .iter()
        .any(|fragment| normalized.contains(fragment))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PLACEHOLDER_PREFIX;

    const SALT: &[u8] = b"deterministic-test-salt";
    const API_KEY: &str = "sk-ant-api03-cache-stable-abcDEF123456";
    const RRN: &str = "670125-1230644";

    #[test]
    fn post_tool_use_read_redacts_string_and_records_mapping() {
        let payload = json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": format!("key {API_KEY}, rrn {RRN}")
        });
        let verdict = claude_code_hook_verdict(&payload, SALT, PathResolution::NotSensitive);
        let output = verdict.output().to_string();
        assert!(!output.contains(API_KEY));
        assert!(!output.contains(RRN));
        assert!(output.contains(PLACEHOLDER_PREFIX));
        let (_, mapping) = verdict.into_parts();
        assert_eq!(mapping.len(), 2);
    }

    #[test]
    fn post_tool_use_clean_or_unrelated_tool_is_noop_json() {
        let clean = json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": "ordinary source"
        });
        assert_eq!(
            claude_code_hook_verdict(&clean, SALT, PathResolution::NotSensitive).output(),
            &json!({})
        );
        let unrelated = json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Write",
            "tool_response": format!("key {API_KEY}")
        });
        assert_eq!(
            claude_code_hook_verdict(&unrelated, SALT, PathResolution::NotSensitive).output(),
            &json!({})
        );
    }

    #[test]
    fn user_prompt_submit_blocks_and_names_types_not_values() {
        let payload = json!({
            "hook_event_name": "UserPromptSubmit",
            "prompt": format!("deploy with {API_KEY}, identity {RRN}")
        });
        let verdict = claude_code_hook_verdict(&payload, SALT, PathResolution::NotSensitive);
        assert_eq!(verdict.output()["decision"], "block");
        let reason = verdict.output()["reason"].as_str().unwrap();
        assert!(reason.contains("ANTHROPIC_KEY"));
        assert!(reason.contains("RRN"));
        assert!(!reason.contains(API_KEY));
        assert!(!reason.contains(RRN));
    }

    #[test]
    fn pre_tool_use_denies_sensitive_read_and_edit_paths() {
        for (tool, path) in [
            ("Read", "/project/.env.local"),
            ("Edit", "/keys/server.pem"),
            ("Write", "/home/u/.ssh/id_rsa.backup"),
        ] {
            let payload = json!({
                "hook_event_name": "PreToolUse",
                "tool_name": tool,
                "tool_input": { "file_path": path }
            });
            let verdict = claude_code_hook_verdict(&payload, SALT, PathResolution::NotSensitive);
            assert_eq!(
                verdict.output()["hookSpecificOutput"]["permissionDecision"],
                "deny"
            );
        }
    }

    #[test]
    fn is_sensitive_path_covers_key_variants_and_windows_gnupg() {
        // Renamed / backup variants of every SSH key type are sensitive.
        for path in [
            "/home/u/.ssh/id_rsa_backup",
            "/home/u/.ssh/id_ed25519_old",
            "/home/u/.ssh/id_ecdsa.bak",
            "/home/u/.ssh/id_dsa2",
        ] {
            assert!(is_sensitive_path(path), "expected sensitive: {path}");
        }
        // Public halves stay allowed for every key type.
        for path in ["/home/u/.ssh/id_rsa.pub", "/home/u/.ssh/id_ed25519.pub"] {
            assert!(!is_sensitive_path(path), "expected allowed: {path}");
        }
        // `.gnupg` private material is denied on both separator styles. Uses a
        // `.gpg` basename (not a sensitive extension) so only the normalized
        // fragment match can catch the Windows form.
        assert!(is_sensitive_path("/home/u/.gnupg/secring.gpg"));
        assert!(is_sensitive_path(r"C:\Users\me\.gnupg\secring.gpg"));
        // Relative paths (no leading slash) are caught too.
        assert!(is_sensitive_path(".aws/credentials"));
        assert!(is_sensitive_path(".gnupg/secring.gpg"));
    }

    #[test]
    fn resolved_sensitive_target_is_denied() {
        let payload = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": { "file_path": "/project/config" }
        });
        assert_eq!(
            claude_code_hook_verdict(&payload, SALT, PathResolution::NotSensitive).output(),
            &json!({})
        );
        assert_eq!(
            claude_code_hook_verdict(&payload, SALT, PathResolution::Sensitive).output()["hookSpecificOutput"]
                ["permissionDecision"],
            "deny"
        );
    }

    #[test]
    fn unresolved_path_is_denied_conservatively() {
        let payload = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": { "file_path": "config" }
        });
        // A resolvable, non-sensitive path stays allowed…
        assert_eq!(
            claude_code_hook_verdict(&payload, SALT, PathResolution::NotSensitive).output(),
            &json!({})
        );
        // …but a transport that could not resolve the path at all must deny —
        // silently skipping the symlink check is the issue #55 bypass.
        let verdict = claude_code_hook_verdict(&payload, SALT, PathResolution::Unresolved);
        let output = &verdict.output()["hookSpecificOutput"];
        assert_eq!(output["permissionDecision"], "deny");
        let reason = output["permissionDecisionReason"].as_str().unwrap();
        assert!(
            reason.contains("could not be resolved"),
            "reason must surface that resolution failed: {reason}"
        );
    }

    #[test]
    fn unresolved_path_does_not_affect_other_events_or_tools() {
        // `Unresolved` is a PreToolUse-only signal: an unrelated tool or event
        // must stay a no-op even when the transport reports it.
        let unrelated_tool = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": "ls config" }
        });
        assert_eq!(
            claude_code_hook_verdict(&unrelated_tool, SALT, PathResolution::Unresolved).output(),
            &json!({})
        );
        let post_tool_use = json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": "ordinary source"
        });
        assert_eq!(
            claude_code_hook_verdict(&post_tool_use, SALT, PathResolution::Unresolved).output(),
            &json!({})
        );
    }

    #[test]
    fn unknown_event_is_noop_json() {
        let payload = json!({ "hook_event_name": "SessionStart" });
        assert_eq!(
            claude_code_hook_verdict(&payload, SALT, PathResolution::NotSensitive).output(),
            &json!({})
        );
    }

    #[test]
    fn verdict_is_byte_stable_for_same_salt() {
        let payload = json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": format!("key {API_KEY}")
        });
        let first = serde_json::to_vec(
            claude_code_hook_verdict(&payload, SALT, PathResolution::NotSensitive).output(),
        )
        .unwrap();
        let second = serde_json::to_vec(
            claude_code_hook_verdict(&payload, SALT, PathResolution::NotSensitive).output(),
        )
        .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn deeply_nested_output_fails_closed() {
        let mut response = json!(format!("deep {API_KEY}"));
        for _ in 0..(MAX_REDACT_DEPTH + 20) {
            response = json!([response]);
        }
        let payload = json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": response
        });
        let output = claude_code_hook_verdict(&payload, SALT, PathResolution::NotSensitive)
            .output()
            .to_string();
        assert!(!output.contains(API_KEY));
        assert!(output.contains(DEPTH_LIMIT_MARKER));
    }
}
