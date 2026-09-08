---
id: 001
title: "Claude Code Function Hooks for Honmoon"
url: "https://github.com/anthropics/claude-code/issues/91870"
date: 2026-09-08
summary: "Assessment of Anthropic's Function Hooks proposal (claude-code#91870) against the Honmoon Claude plugin: which firewall features a hooks-module could ship, what the prototype in Claude Code 2.1.263 already supports, and the constraints a redactor must design around."
tags: [claude-code, plugin, hooks, redaction, pii, egress-policy]
---

# Claude Code Function Hooks for Honmoon

## Sources

- Proposal thread: <https://github.com/anthropics/claude-code/issues/91870> (136 comments as of 2026-09-08)
- Architecture doc: "Function Hooks: Core Architecture", Alice Poteat, August 2026 (PDF attached to the issue)
- Community prototype of the algebra: <https://github.com/Monte9/claude-function-hooks>
- Current Honmoon plugin: `packages/claude-plugin/` (`honmoon-redact` 0.1.0, command hooks around `honmoon hook`)

## What the proposal is

A fifth hook type beside `command`, `prompt`, `agent`, and `http`: `hooks.json` may name a `modules` entry, a `.ts`/`.js`/`.tsx`/`.jsx` file under `hooks/` that exports `register(on)`. Each hook has the Koa-style signature `($, e, next)`:

| Symbol | Meaning |
| --- | --- |
| `$` | The engine interface. The only door to side effects (`$.fs`, `$.http`, `$.process`, `$.ui`, `$.clock`, `$.store`, ...). No ambient filesystem or network in the hook environment; `claude plugin validate` rejects modules that reach `$` any other way. |
| `e` | The immutable event object, i.e. the argument the `$` method was called with. On `tool.call` it is the tool name plus its structured arguments. |
| `next` | The continuation. `next(e)` runs the rest of the chain and resolves to the event's result. Carries `next.signal`, `next.is`, `next.event`, `next.origin`. |

Key properties:

- **Order is nesting.** `on(X, A), on(X, B), on(X, C)` folds to `A(B(C(core)))`. Earlier registration wraps more and therefore holds more authority. Plugin order is admin-prepended, then dependency order, then admin-appended, then builtin, then core.
- **Five placements on one event** (before, after, during, instead, modifying) replace today's Pre/Post pair. Not calling `next` is how a tool is prevented from running; the return value is what the model is told happened.
- **Every method on `$` is a hookable event**, including calls other plugins make. A hook on `*` sees everything, which makes an audit log one function.
- **`engine.create`** builds `$` at startup as its own chain; an org-prepended plugin can withhold nouns (for example `$.http`) from every plugin beneath it. This is the mechanical "blast door" for admins (doc section 4.2).
- **`ui.render`** is hooked like any event, matched on `component` and `surface`, so a plugin can wrap or replace the rendering of `ToolUse`, `AskUserQuestion`, and so on. Interaction events (`ui.press`) flow through the same chain.
- **Enterprise management stays a file**: admins list prepended and appended plugins in managed settings. Which plugins may load is itself a hook on `plugin.register`.

## State of the prototype (verified locally)

Claude Code 2.1.263 installed on this machine contains the flagged prototype. Strings present in the binary:

| String | Present |
| --- | --- |
| `CLAUDE_CODE_ENABLE_FUNCTION_HOOKS` | yes |
| `plugin-types` (the `/plugin-types` typings command) | yes |
| `"modules"` in hooks.json | yes |
| `tool.call`, `engine.create`, `ui.render`, `$.http` | yes |
| `classic.PreToolUse` (wrapper events for existing shell hooks) | no |
| `next.to` (tier skipping: prepend, user, append, builtin, core) | no |

The `classic.*` and `next.to` designs are described by the maintainer as internal only. Commenters measured the shipped engine on 2.1.260 through 2.1.263 with:

```sh
CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1 claude -p --plugin-dir <dir> --debug-file ./d.log "..."
```

with `hooks/hooks.json` set to `{"modules": ["./probe.ts"]}` and `import type { Register } from "claude-code"` for typings. Whether the feature ships at all is explicitly tied to the community response on the thread.

Measured behaviors that matter for a security plugin:

- A hook that **throws**, **exceeds its 10 000 ms budget**, or returns neither `{ result }` nor `{ deny }` is **skipped and the tool runs anyway**, logged only to `--debug-file` as `hook failed: <plugin>: ... (tool.call; skipped; what is below it ran in its place)`. Fail-open by default.
- `{ deny: "reason" }` returned without calling `next` blocks the tool on 2.1.261+ and the model receives the reason as the tool's error result. `{ deny: "" }` was a silent no-op on 2.1.260 and is fixed in 2.1.261.
- Calling `next` twice, or returning a deny after `await next(e)`, does not undo the effect.
- One `on("tool.call")` per event per plugin: on 2.1.263 a second registration from the same plugin silently replaces the first (earlier prototype builds reportedly threw), so a before-check and an after-redaction have to share a single hook rather than one hook per placement. A chain of N independent hooks still means N plugin directories.
- `claude plugin validate` checks that `$` is used syntactically, not that the noun exists at runtime (`$.fs.read` passes validation and throws at dispatch).
- The model sees what it **asked** to write, not the rewritten value, for prompt-cache reasons. A rewriting hook should attach a `context` note describing the change; the maintainer is considering making it required in some cases.
- `$.prompt.submit` refuses text beginning with `/` (host check), so a plugin cannot trigger `/compact`.
- Maintainer's stated placement for a redactor: org-**appended**, so it sits closest to core and no higher plugin ever receives the unredacted result:

```ts
on("tool.call", async ($, e, next) =>
  recursiveStrReplace(await next(e), /secret/g, "[REDACTED]"))
```

## What the current Honmoon plugin does and where it stops

`honmoon-redact` ships three command hooks, all shelling out to `honmoon hook`:

| Event | Behavior | Limit |
| --- | --- | --- |
| `PostToolUse` on Read, Bash, Grep | Rewrites the tool result via `updatedToolOutput` with stable placeholders. Verified on 2.1.263 that the persisted transcript stores the redacted value. | Only those three tools. MCP results, WebFetch, and subagent output are not covered. |
| `UserPromptSubmit` | Blocks a prompt that carries a secret or a high-severity identifier. | A command hook cannot rewrite a prompt, so the user must edit and resubmit. |
| `PreToolUse` on Read | Denies reads of known credential files. | Matches on path only. |

Other documented limits: the redaction is one-way (no reverse substitution; the tokenizer mapping is not shared with the proxy), and every hook pays a process spawn. The README already names an HTTP transport to the management API as the planned follow-up.

## Features Honmoon could ship as a hooks-module

1. **Secret and PII redaction on `tool.call`.** Case study ⓼ in the issue. `await next(e)`, run the Tier-1 detectors over the result, return the redacted result plus a `context` note with the replacement count. Covers every tool including MCP and WebFetch. Two commenters said this is the hook they tried to write with the current API and could not.
2. **Prompt rewriting on `prompt.submit`.** Redact and forward instead of blocking; removes the main friction in today's plugin.
3. **Egress policy at the tool layer.** A `tool.call` hook on Bash, WebFetch, and MCP tools sees structured arguments rather than a regex over a shell string, consults the gateway's allow/deny/pause policy over `$.http`, and returns a deny reason the model reads. Pause can become an in-terminal approval instead of a dashboard round trip. Complements the proxy: proxy is wire-level enforcement, hook is intent-level.
4. **Audit log on `*`.** A prepended hook sees every event, including other plugins' `$` calls and denied operations, and ships them to Honmoon's audit store or dashboard.
5. **Capability withholding on `engine.create`.** An org-prepended Honmoon plugin removes `$.http` and `$.process` from plugins below it. This is the closest fit to Honmoon's positioning as an admin-controlled firewall.
6. **Render hooks.** `ui.render` on `ToolUse` to badge redacted counts or hide placeholders until hover (case study ⓽), and to show policy verdicts inline.
7. **Reverse substitution.** With the hook in-process and able to reach the management API, the placeholder mapping can be shared with the proxy, lifting the one-way limitation.

## Design constraints

- **Transport.** The hook environment has no ambient network or filesystem, so the Rust engine in `honmoon-core` cannot be called directly. Options: `$.process.run` (same spawn cost as today), `$.http.fetch` to a management API endpoint (maintainer-recommended pattern for local daemons; matches the README's planned HTTP transport), or a TypeScript/WASM port of the detectors in-process. HTTP is the best fit for a first cut; WASM later if latency matters.
- **Fail closed.** Because a thrown or timed-out hook is skipped, the redactor must catch every error and return a deny (or a fully redacted placeholder) rather than let the raw result through. Ship a regression fixture that asserts a detector failure fails closed.
- **Position.** Register as an org-appended plugin so it is the last hook above core. Combined with the withholding hook (prepended), Honmoon would occupy both ends of the chain.
- **Context note.** Every rewrite attaches `context` so the model is not reasoning about content it never saw.
- **Coexistence.** The doc states a hooks-module and existing `hooks.json` entries run side by side. Keep the command hooks as the fallback for Claude Code versions without the flag.
- **Budget.** Detector calls must stay well inside the 10 s per-hook budget; the proxy's per-request latency numbers apply.
- **Stability.** The API is pre-release; `classic.*`, `next.to`, typed errors, and result merging across hooks are all still open on the thread. Expect churn.

## Proposed next step

Add `hooks/honmoon.ts` to `packages/claude-plugin` behind `CLAUDE_CODE_ENABLE_FUNCTION_HOOKS`, implementing items 1 and 2 over an `honmoon hook` HTTP endpoint on the management API, with a fail-closed regression test. Items 3 through 7 follow once the transport is proven.
