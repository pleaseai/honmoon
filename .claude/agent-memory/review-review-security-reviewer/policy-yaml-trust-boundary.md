---
name: policy-yaml-trust-boundary
description: Policy YAML is trusted local author input — loaded only from a local file path; the mgmt API exposes GET /api/policy and no write/upload route
metadata:
  type: project
---

Policy YAML in honmoon is **trusted author input**, not untrusted data.

**Why:** the only load paths are `honmoon-cli/src/main.rs` `gateway()` (`std::fs::read_to_string(&config)` → `Policy::from_yaml`) and `load_policy()`; `honmoon-mgmt/src/lib.rs` registers `/api/policy` with `get(get_policy)` only — there is no POST/PUT policy upload or hot-reload route. So rule names, endpoint names and conditions are written by whoever owns the config file, i.e. the same principal that runs the gateway.

**How to apply:** do NOT report log injection / ANSI-forging / information-disclosure findings for `tracing::warn!` calls in `Policy::from_yaml` (`warn_undefined_endpoints`, `warn_shadowed_rules`) that interpolate `rule.name` / `rule.endpoint` — the strings are author-controlled. Same for O(n^2) load-time passes over `policy.rules`: the rule list is a hand-written file, not attacker-sized. Re-verify this memory if a policy-write route (reload/upload) ever appears in `honmoon-mgmt` — that would move the boundary and make all of the above live.

Related: [[postgres-refusal-ordering-barrier]] (ADR-0007 connection-allow-last ordering is why shadowed-rule warnings exist at all).
