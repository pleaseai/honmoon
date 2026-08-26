---
name: run-honmoon
description: Build, launch, and drive the Honmoon policy firewall gateway — run the gateway, probe egress policy (allow/deny/pause), resolve approvals, exercise TLS interception and secret redaction, screenshot the dashboard, and run the test suites. Use when asked to run, start, build, test, or screenshot honmoon, the gateway, the proxy, or the dashboard.
---

# Run Honmoon

Honmoon is a policy firewall gateway for AI agents: a Rust data plane (HTTP
CONNECT proxy + optional TLS interception) with an axum management API and a
React dashboard **embedded into the same binary**. One process serves both the
proxy and the dashboard.

Drive it with the committed harness — it wraps build, launch, probing, the
approval queue, the redaction engine, and dashboard screenshots:

```bash
node .claude/skills/run-honmoon/driver.mjs <command>
```

All paths below are relative to the repo root. Verified on macOS (darwin) with
`cargo 1.98.0`, `bun 1.4.0`, `node 24`.

## Prerequisites

Already present via `mise` (`mise.toml` pins node + bun; `rust-toolchain.toml`
drives rustup). Nothing to `apt-get` / `brew install`:

```bash
mise install          # node 24 + bun
bun install           # JS workspace deps
```

The driver screenshots via `agent-browser` (installed globally); there is no
`chromium-cli` on this machine.

Inside an Orca session, Orca's own embedded browser is the org-preferred backend
and shares your logged-in GitHub/app session — which `agent-browser` does not.
Its commands are `orca tab create --url … --json`, then `orca snapshot`, `goto`,
`click`, `upload`, `eval`, `screenshot` (all `--json`). **There is no
`orca browser` subcommand** — probing that name returns `Unknown command:
browser` and wrongly suggests Orca cannot drive a browser at all. Reach for it
over `agent-browser` whenever a page needs your real session.

## Build

```bash
node .claude/skills/run-honmoon/driver.mjs build
```

Dashboard first, then cargo — that order matters. `honmoon-mgmt` embeds
`apps/dashboard/dist` via `rust-embed`; `build.rs` substitutes a placeholder when
that directory is missing, so **a bare `cargo build` succeeds and silently gives
you a blank dashboard**. Cold Rust build ≈ 75s; incremental ≈ 3s.

Equivalent by hand:

```bash
bun run --filter '@honmoon/dashboard' build
cargo build --workspace
```

## Run (agent path)

```bash
# Full end-to-end: build → launch → probe → approve → redact → screenshot → teardown
node .claude/skills/run-honmoon/driver.mjs smoke
node .claude/skills/run-honmoon/driver.mjs smoke --mitm   # + TLS interception & wire redaction
```

Or drive it step by step:

```bash
node .claude/skills/run-honmoon/driver.mjs up              # launch (writes a demo policy)
node .claude/skills/run-honmoon/driver.mjs up --mitm --redact --pii-mode detect
node .claude/skills/run-honmoon/driver.mjs status
node .claude/skills/run-honmoon/driver.mjs logs

node .claude/skills/run-honmoon/driver.mjs probe https://github.com
node .claude/skills/run-honmoon/driver.mjs probe https://example.com

node .claude/skills/run-honmoon/driver.mjs approvals       # held-request queue
node .claude/skills/run-honmoon/driver.mjs approve 1       # resolve via the mgmt API
node .claude/skills/run-honmoon/driver.mjs deny 1
node .claude/skills/run-honmoon/driver.mjs ui-approve      # resolve by CLICKING in the dashboard
node .claude/skills/run-honmoon/driver.mjs ui-approve --deny

node .claude/skills/run-honmoon/driver.mjs audit 20
node .claude/skills/run-honmoon/driver.mjs shot mypage     # dashboard screenshot
node .claude/skills/run-honmoon/driver.mjs down
```

State lands in `target/honmoon-run/` (gitignored): `gateway.pid`, `gateway.log`,
`audit.jsonl`, `policy.yaml`, `ca.pem`, `shots/*.png`.

Defaults are the CLI's own: proxy `127.0.0.1:8443`, dashboard `127.0.0.1:8444`.
Override with `HONMOON_ADDR` / `HONMOON_MGMT_ADDR`.

`probe` translates curl's exit code into the verdict — a denied CONNECT is
`403` and `curl` exits **56**, an approved-after-hold request exits 0, and a
hold that times out exits 28.

`--redact` and `--pii-mode block` both require `--mitm`; the driver rejects the
combination rather than starting a gateway with semantics you did not ask for.

### Direct invocation (no gateway, no network)

Most recent PRs touch the redaction engine (`hook.rs`, `secret_tokenizer/`,
`pii.rs`) rather than the proxy. Hit that layer directly:

```bash
node .claude/skills/run-honmoon/driver.mjs hook 'aws key AKIAIOSFODNN7EXAMPLE, email alice@example.com'
# → aws key <<hs:9f77c1aa…>> and email <<hs:164d279b…>>
```

or straight at the binary (this is the Claude Code hook transport):

```bash
echo '{"hook_event_name":"PostToolUse","tool_name":"Read","tool_response":"key AKIAIOSFODNN7EXAMPLE"}' \
  | ./target/debug/honmoon hook --salt-context demo
```

Placeholders must be **byte-identical across runs for the same salt** — that is
what keeps re-sent conversation history prompt-cache stable. The `smoke` command
asserts it (and rejects a vacuous pass where nothing was redacted at all).

**`honmoon hook` writes nothing to stdout when there is nothing to redact** —
the verdict is `{}` and the binary skips the write entirely
(`crates/honmoon-cli/src/hook.rs:54`), still exiting 0. Parsing stdout as JSON
unconditionally therefore blows up on every clean payload. Treat empty output as
"no redaction needed", not as failure; the driver's `hook` prints
`(nothing to redact)`.

## Run (human path)

```bash
./target/debug/honmoon gateway --config policies/agent.yaml --audit-log honmoon-audit.jsonl
# proxy http://127.0.0.1:8443 · dashboard http://127.0.0.1:8444 · Ctrl-C to stop
cd apps/dashboard && bun run dev     # dashboard HMR, proxies /api to :8444
```

`honmoon run --policy policies/agent.yaml -- <cmd>` wraps a single command's
egress. It works:

```bash
./target/debug/honmoon run --policy policies/agent.yaml -- curl -s -o /dev/null -w '%{http_code}\n' https://github.com   # 200
```

`honmoon join` is **not implemented** — it bails with an error.

## Test

```bash
cargo test --workspace     # 225 tests, ~15s
bun test                   # 9 tests
```

## Gotchas

- **`github.com` on the allowlist does not permit `api.github.com`.** Matching is
  exact unless the pattern starts with `*.`; `*.foo.com` matches both `foo.com`
  and its subdomains (`crates/honmoon-core/src/engine.rs:81`). The README's own
  example — `honmoon run --policy policies/agent.yaml -- curl https://api.github.com`
  — is **denied** by `policies/agent.yaml`. Allowlist `*.github.com` if you want
  subdomains.

- **`http.method` and `http.path` are empty strings on a CONNECT.** Without
  `--tls-intercept` the proxy never sees inside the tunnel, so a rule like
  `http.host == 'x' && http.path == '/post'` compiles fine and *silently never
  fires* (a condition that errors or misses simply does not match — fail-closed).
  Key host-level pause rules on `http.host` alone. This cost a debugging round
  while writing this skill.

- **Rules are evaluated before the egress allow/deny lists.** A `pause` rule
  fires on a host that is not on the allowlist at all — that is how the driver
  holds `example.org` without allowlisting it.

- **`pause` cannot be expressed in the egress lists** — those only yield
  allow/deny. It needs a `rules:` entry, and `endpoint: '*'` is what matches a
  CONNECT (`facts.endpoint` is `None` there, and only the literal `*` matches).

- **A client that gives up resolves its own hold.** When `curl` hits `--max-time`
  and disconnects, the held request is rejected server-side and its id leaves the
  queue — a later `deny <id>` then returns `404 {"error":"no such pending
  approval"}`. Keep the client waiting (the driver's `probeAsync` allows 120s)
  while you resolve it. Holds nobody touches auto-reject after 300s.

- **`--ca-cert` and `--ca-key` require each other *and* `--tls-intercept`.**
  Omit them and the CA is generated in-memory and ephemeral, so no client can
  ever trust it. Always pass explicit paths when testing MITM, then
  `curl --cacert <path>`.

- **A TLS-intercepted request writes two audit events**, not one: the CONNECT
  (`body_size: 0`, empty method/path) and the decrypted inner request (real
  method/path, plus `pii` facts). Expect the count to double under `--mitm`.

- **Wire redaction looks like a no-op from the client** — the response is
  *detokenized* on the way back, so an echo service returns your original
  secret. The proof that upstream got placeholders is the byte count: a 64-byte
  body carrying a 20-char AWS key and a 17-char email arrives upstream as **105**
  bytes (64 − 20 − 17 + 39 + 39; each placeholder is exactly 39 chars). `smoke
  --mitm` prints all three numbers.

- **Tier-1 PII is `EMAIL`, `PHONE`, `CREDIT_CARD`, `IP`, `RRN`** (Korean
  resident-registration number) — checksum/format-validated labels only. A US
  SSN like `123-45-6789` is **not** redacted; don't use one as your test string
  and conclude redaction is broken.

- **Dashboard nav buttons embed their pending count** — the accessible name is
  `"Approvals 2"`, so `agent-browser find text "Approvals" click` fails with
  "Element not found". Resolve the ref from `agent-browser snapshot` and click
  `@e12`. The driver's `clickNav` does this.

- **`agent-browser` refs are renumbered whenever the DOM changes.** Re-snapshot
  before every click; a ref captured before a previous click may now point
  somewhere else.

- **In debug builds `rust-embed` reads the dashboard from disk at runtime**, so
  a `vite` rebuild shows up on refresh without recompiling Rust. Release builds
  bake the assets in.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `curl: (56) CONNECT tunnel failed, response 403` | Working as designed — policy denied the host. Check the exact hostname against the allowlist (see the subdomain gotcha). |
| Request hangs ~30s then `curl: (28)` | It hit a `pause` rule and no one resolved it. `driver.mjs approvals` then `approve <id>`. Unresolved holds auto-reject after 300s. |
| `curl: (60) SSL certificate problem` under `--mitm` | Pass `--cacert target/honmoon-run/ca.pem`, and make sure the gateway was started with explicit `--ca-cert`/`--ca-key` (otherwise the CA is ephemeral). |
| Dashboard loads but is blank | `apps/dashboard/dist` was missing at compile time, so `build.rs` embedded a placeholder. Build the dashboard, then rebuild cargo. |
| `error: the following required arguments were not provided: --ca-key` | `--ca-cert` and `--ca-key` are mutually required and both need `--tls-intercept`. |
| `gateway did not become healthy` | Read `target/honmoon-run/gateway.log`. Usually port 8443/8444 is already held by an earlier run — `driver.mjs down`, or set `HONMOON_ADDR`/`HONMOON_MGMT_ADDR`. |
| `honmoon: command not found` | The binary is `./target/debug/honmoon`; it is not installed on PATH. |
| `join` errors out immediately | Not implemented yet — expected. |
| `agent-browser` "Element not found" | The name probably carries a badge count. Use `snapshot` + `@ref`. |
