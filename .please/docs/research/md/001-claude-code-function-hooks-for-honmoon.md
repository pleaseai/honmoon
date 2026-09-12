---
id: 001
title: "Claude Code Function Hooks for Honmoon"
url: "https://github.com/anthropics/claude-code/issues/91870"
date: 2026-09-11
summary: "Assessment of Anthropic's Function Hooks proposal (claude-code#91870) against the Honmoon Claude plugin: which firewall features a hooks-module could ship, what Claude Code 2.1.268 supports, and the constraints a redactor must design around. Anthropic has since committed to shipping it as 'Claude Mods', published the built-in mod sources, and made fail-closed declarable via .catch."
tags: [claude-code, plugin, hooks, mods, redaction, pii, egress-policy]
---

# Claude Code Function Hooks for Honmoon

## Sources

- Proposal thread: <https://github.com/anthropics/claude-code/issues/91870> (159 comments as of 2026-09-11; OP updated 2026-09-09)
- Architecture doc: "Function Hooks: Core Architecture", Alice Poteat, August 2026 (PDF attached to the issue)
- Community prototype of the algebra: <https://github.com/Monte9/claude-function-hooks>
- Built-in mod sources: <https://github.com/anthropics/claude-code/tree/main/mods> (`sec-default`, `diff`, `telemetry`), published 2026-09-09
- `$` cheat sheet: the SVG attached to the updated OP, "Claude Mods · the $ cheat sheet", Anthropic, 2026-09-09
- Typings read locally: `/plugin-types` on Claude Code 2.1.268 (`claude-code.d.ts`, 313 KB)
- Current Honmoon plugin: `packages/claude-plugin/` (`honmoon-redact` 0.1.0, command hooks around `honmoon hook`)

## Update — 2026-09-11: committed to ship, named "Claude Mods"

The maintainer updated the OP on 2026-09-09. Three things changed the standing of this note.

**It is shipping.** Anthropic is "committed to shipping function hooks, on the scale of weeks in
lieu of days or months". The feature is being productized as **Claude Mods**; "function hook" stays
as the documented implementation primitive. A mod is just a plugin whose behaviour lives in a hooks
module — nothing about the plugin format changes. `CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1` is now
publicly acknowledged for testing, and the stated intent is to migrate further existing Claude Code
features into mod form. The semantics are described as largely settled, with fewer breaking changes
expected than in the first week.

**The built-in mods are open source.** `mods/` in the claude-code repo carries the full source of
three mods as built into the binary: `sec-default`, `diff`, `telemetry`. `sec-default` is the one
that matters here — see below.

**The prototype moved 2.1.263 → 2.1.268.** Several things this note listed as absent or as
constraints have landed.

### What landed since 2.1.263

| Item | 2.1.263 | 2.1.268 | Why it matters for Honmoon |
| --- | --- | --- | --- |
| `.catch()` on a registration | absent | **present** | Fail-closed is now declarable. This removes the note's single largest design constraint. |
| `next.to(e, tier)` | absent | **present** (managed tiers only) | An org-tier mod can continue past the user tier. The mechanism `sec-default` is built on. |
| `classic.*` | absent | **present** | Every settings hook is wrapped 1:1 as `classic.<Event>`, exact JSON in and out. A migration path for `honmoon-redact`'s existing command hooks. |
| `next.origin` | string | **`{ plugin, tier }`** | A hook can decide by the caller's tier, not just its name. |
| `next.trace` | — | **present** | After `await`: each lower link's plugin, tier, `e`, result, outcome. An audit log gets the chain, not just the event. |
| `$.fs.readFile/listDir` | that spelling | **`$.fs.read` / `.write` / `.list`** | The rename the thread predicted has landed; anything written against 2.1.263 breaks. |
| `$.mcp.call` | — | **present as a noun, so hookable** | Answers the thread's open question: MCP tool calls are on `$` and can be gated. Closes the gap where MCP is invisible to a Bash/WebFetch-only guard. |
| `tool.check` | absent | still absent | Announced in the cheat sheet and in `sec-default`'s pass-list; a guard-only event that lets independent guards run concurrently. Forthcoming. |
| `plugin.register` | absent | still absent | The admission hook the supply-chain use case needs. Forthcoming. |

### Fail-closed, resolved

The note's "Fail closed" constraint said a redactor must catch everything itself because a thrown or
timed-out hook is skipped. That is now a declared property of the registration:

```ts
on("tool.call", { tool: "Bash" }, async ($, e, next) => { /* ... */ })
  .catch(($, e, next) =>
    next.called ? next(e) : { deny: next.error.kind })
```

Verified in the 2.1.268 declarations:

- `CatchHandler` runs the hook's own `($, e, next)` afresh when it **throws, misreturns, or overruns**.
- `next.error` is `HookFailure`: `{ kind: 'throw' | 'timeout', message?, budget }`, where `budget` is
  the grace in ms the handler itself gets. Past that grace the hook is absent as if it had no handler
  — so the handler must be cheap, and a fail-closed handler should return `{ deny }` directly rather
  than do work.
- `next.called` says whether the failed hook had already dispatched.
- Inside the handler `next` is **replay-safe**: when `called`, `next(e)` resolves to what the hook's
  last call settled to without re-running anything beneath; when not, it runs the chain beneath once.
- Returning `undefined` from the handler means "the hook was absent" (i.e. `await next(e)`) — which is
  the fail-*open* choice, so a security hook must never fall off the end of its handler.

**Consequence for Honmoon:** the planned regression fixture asserting a detector failure fails closed
is still required, but it now tests a supported contract instead of a workaround. Drop the
`Promise.race` pattern the maintainer suggested mid-thread.

### `sec-default`: Anthropic's own admin-firewall mod

`mods/sec-default` is a reference implementation of exactly the posture item 5 of this note proposed
for Honmoon — an org plugin seated outermost that constrains what user-tier plugins can reach. Worth
reading in full before writing `hooks/honmoon.ts`; it is ~25 small files and the whole policy is one
`register.ts`.

What it establishes:

- **The tier ladder is five deep and explicit**: `prepend` (org) → `user` (what a person installs) →
  `append` (org) → `builtin` → `core`. Authority decreases toward core. On the way down each link may
  refine `e` (append is last before the product); on the way up each may refine the result (prepend is
  last before the engine acts). **An org holds both ends** — which is the seat Honmoon wants.
- **Three moves and nothing else**: continue past the user tier (`next.to(e, "append")`), refuse a
  user-tier caller by name (`{ deny }` when `next.origin.tier === "user"`), or pass (`next(e)`).
- **Provenance is `e.provider.tier`**, pinned on the event, and it is typed *loosely on purpose*
  (`{ readonly provider?: { readonly tier?: unknown } | null }`) so a missing or odd provider fails
  closed. Good pattern to copy.
- **Policy is read via `$.settings.read({ source: "policy" })`**, memoized per burst, and an unreadable
  policy counts as a policy in force.
- **Seating is admin-controlled**: the CLI seats `sec-default` first in the prepend tier on a machine
  with managed settings or a Team/Enterprise org, *unless* managed settings define `prependPlugins` —
  then that list is the whole prepend tier and the org names `sec-default@builtin` in it, or does not.
  So an org can order Honmoon relative to it: `"prependPlugins": ["honmoon@...", "sec-default@builtin"]`.
- `next.to` **is refused outside a managed tier**. Loading a mod with `--plugin-dir` seats a plugin that
  can only pass. Honmoon's withholding features therefore only work when installed through managed
  settings, not by a developer locally. This is a deployment constraint the note did not have.

Note the overlap: `sec-default` explicitly "adds no policy of its own" — it protects the org's
existing controls (classic hooks, managed CLAUDE.md, settings reads, MCP allowlist) from user-tier
plugins. It does not do egress policy, redaction, or audit. Honmoon is complementary, not displaced.

### `$` as of 2.1.268

67 verbs are registered as events, extracted from the generated declarations:

```
agent.list agent.offer agent.spawn attribution.text audio.play audio.speak
command.describe command.list command.register command.run engine.create
env.get env.set fs.ancestors fs.exists fs.list fs.read fs.stat fs.write
http.fetch mcp.call model.classify model.complete model.fork process.run
prompt.context prompt.fill prompt.section prompt.submit prompt.suggest
session.authorize session.compact session.cwd session.id session.messages
session.model session.receive session.repo session.start session.surface
session.turns session.usage settings.read skill.prompt
store.delete store.get store.keys store.set
tool.call tool.describe tool.list tool.register turn.abort turn.complete
turn.start turn.step ui.close ui.input ui.invalidate ui.log ui.message
ui.notice ui.open ui.press ui.render ui.resolve ui.select ui.status ui.toast
```

plus the `classic.<Event>` family (`classic.PreToolUse`, `classic.Stop`, `classic.PermissionRequest`, …).

Newly relevant to a firewall: `$.mcp.call` (gate MCP), `$.settings.read` (read managed policy),
`$.env.get/set` (by literal name only; `validate` lists what is read and written), `$.session.messages`
and `$.session.usage` (transcript and context/cost), `$.model.classify` (cheap label over a text — a
possible detector escape hatch), `$.command.run` (the correct way to invoke a slash command; the
maintainer confirmed `$.prompt.submit("/x")` is deliberately refused).

### Rules of the road worth designing against

From the cheat sheet, each a hard property rather than a convention:

- **Spelling is the contract.** `$` must be written `$.noun.verb(…)` literally and `on("event")`
  literally; the loader inventories both and refuses what it cannot see. No computed noun access, no
  dynamic event names.
- **Ids on `e` are pinned** (`tool`, `tool_use_id`, `agentId`, `origin`, `provider`, `trigger`, keys);
  the rest of the payload is yours to rewrite. So a redactor may rewrite content but cannot forge
  identity.
- **Recursion is cut**: a hook never sees the dispatches it raised — its own `$` calls, its `next`, its
  spawned agent. Sibling hooks and everyone else do. An audit hook on `*` therefore cannot loop on
  itself, which makes item 4 of this note safe to build.
- **Plugins are trusted code with the process's reach.** `$.fs` is the host filesystem, not a workspace
  sandbox — this answers the thread's open question the note carried. Orgs govern by *admission*
  (a hook on `plugin.register`, forthcoming), not by sandboxing.
- **Agents are a separate axis from origin**: `tool.call` inside a subagent carries `agentId`, and
  `$.agent.list()` maps it to `name`, `parentId`, `type`. Per-agent policy — which the thread showed is
  impossible with command hooks, since subagents are handed the parent's `session_id` and
  transcript_path — becomes possible.
- **Hot reload**: `claude --plugin-dir ./my-mod` reloads on save.

### Concurrency

The serial-onion cost a commenter measured (eight independent 300 ms guards: 640 ms as command hooks,
2427 ms folded) is avoidable today by starting `next(e)` before doing local work and only awaiting it
when the result must be transformed. For guards that only decide, `tool.check` (forthcoming) is the
intended event: its core is not the action, so guards over it can fold concurrently. A redactor, which
must transform the result, is structurally serial and stays on `tool.call`.

### Still open on the thread

- Whether a `modifying` placement's rewritten call is re-evaluated by the rest of the chain (including
  the auto-mode classifier) — decides whether a rewrite can *widen* a grant.
- Ownership of an outstanding downstream promise when an outer hook denies after starting `next(e)`.
- A declared contract/version field so a `$` rename does not break every mod on update.
- Whether a hook can be invoked against a synthetic event from CI — the testability ask, unanswered.

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

## State of the prototype (verified locally, 2.1.263)

> Superseded in part by the 2026-09-11 update above: the local CLI is now 2.1.268, where
> `classic.*` and `next.to` **are** present and `$.fs.readFile` has been renamed `$.fs.read`.
> The rest of this section still holds.

Claude Code 2.1.263 contained the flagged prototype. Strings present in the binary:

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
- **Fail closed.** ~~Because a thrown or timed-out hook is skipped, the redactor must catch every error itself.~~ As of 2.1.268 this is declarable: `on(...).catch(($, e, next) => next.called ? next(e) : { deny: next.error.kind })`. The handler runs on a small grace budget, so keep it to a decision. Never return `undefined` from it — that means "hook absent" and fails open. Ship a regression fixture that asserts a detector failure fails closed.
- **Position.** Register as an org-appended plugin so it is the last hook above core. Combined with the withholding hook (prepended), Honmoon would occupy both ends of the chain — the seat `sec-default` documents as "an org holds both ends". Caveat discovered 2026-09-11: `next.to` is refused outside a managed tier, so the withholding half only works when Honmoon is installed through managed settings, not via `--plugin-dir`. Order relative to Anthropic's own mod is set by `prependPlugins`.
- **Context note.** Every rewrite attaches `context` so the model is not reasoning about content it never saw.
- **Coexistence.** The doc states a hooks-module and existing `hooks.json` entries run side by side. Keep the command hooks as the fallback for Claude Code versions without the flag.
- **Budget.** Detector calls must stay well inside the 10 s per-hook budget; the proxy's per-request latency numbers apply. Time spent inside `next(e)` does not count: measured on 2.1.263, a hook wrapping a 12.7 s Bash call still had its rewrite applied, and the debug log reports `settled in 12704.3ms (next() included)` without a skip. Only the hook's own work before and after `next` is budgeted.
- **Stability.** The API is pre-release. As of 2026-09-11 `classic.*`, `next.to` and typed errors have all landed; `tool.check`, `plugin.register`, a contract/version field, and CI-testability of a hook are still open. Anthropic says semantics are largely settled and shipping is weeks away, but `$.fs.readFile` → `$.fs.read` shows renames do land without a compatibility shim. Pin to a verified CLI version and regenerate typings with `/plugin-types` after every update.

## Proposed next step

Add `hooks/honmoon.ts` to `packages/claude-plugin` behind `CLAUDE_CODE_ENABLE_FUNCTION_HOOKS`, implementing items 1 and 2 over an `honmoon hook` HTTP endpoint on the management API, with a fail-closed regression test — now written against `.catch()` rather than a hand-rolled `Promise.race`. Read `mods/sec-default/hooks/register.ts` first; it is the closest published analogue to Honmoon's posture and establishes the tier/provenance idioms to copy. Items 3 through 7 follow once the transport is proven, with item 3 extended to `$.mcp.call` now that MCP is on `$`.
