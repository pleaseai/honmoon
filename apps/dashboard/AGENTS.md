# AGENTS.md — Dashboard (`apps/dashboard/`)

The Honmoon management dashboard: a React + Vite + Tailwind SPA (Phase 4). `App.tsx` is a tab shell
over four live views — Overview, Audit Log, Policies (Prism-highlighted), Approvals (approve/deny)
— polling the management API. Built into `dist/` and **embedded into the Rust binary via
`rust-embed`**, served by `honmoon-mgmt` (`honmoon gateway`).

## Build & Run Commands

```bash
bun install                       # from repo root (workspace)
cd apps/dashboard && bun run dev  # Vite dev server with HMR
bun run --filter '@honmoon/dashboard' build
bun run --filter '@honmoon/dashboard' build:demo  # stock build + demo shim → dist-demo/
# or from root:
bun run dashboard:dev
```

`build:demo` produces the backend-free demo deployed to Cloudflare Pages by
`.github/workflows/deploy-demo.yml`. **Invariant: the app source contains no demo
code and no demo build flag.** `build:demo` runs the ordinary `build`, then
`demo/build.ts` copies the resulting `dist/` to `dist-demo/` (gitignored) and
injects one `<script src="./demo-mode.js">` tag ahead of the app bundle. The demo
is the exact shipped artifact plus that shim — keep it that way: anything a
future demo needs belongs in `demo/`, never behind a flag in `src/`.

Views are hash-routed (no History API, so neither Cloudflare Pages nor the
rust-embed handler needs a rewrite rule). Unknown hashes fall back to Overview:

| hash | view |
|------|------|
| `#/` (or empty) | Overview |
| `#/audit` | Audit Log |
| `#/policies` | Policies |
| `#/approvals` | Approvals |

## Structure

| Path | What |
|------|------|
| `src/main.tsx` / `src/App.tsx` | Entry point; hash router + shell over the four views. |
| `src/components/` | `Overview`, `AuditLog`, `PolicyView`, `Approvals`, plus shared pieces: `DecisionBadge` (glyph + mono verdict pill), `ApprovalActions` (Deny / Approve pair), `ui` (`Panel` double bezel, `PageHead`, `SectionHead`, `ErrorNote`, `PanelState`). |
| `src/api.ts` / `src/hooks.ts` / `src/format.ts` | Typed management-API client, `usePolling` + `useApprovalActions` (per-id busy set), formatters. |
| `src/index.css` | G2 "Barrier Membrane" tokens (oklch, dark primary / light secondary), Tailwind `@theme` bridge, and the few component classes (`bezel`/`glass`, `verdict-*`, `action-*`, Prism YAML token colors). |
| `demo/demo-mode.js` | Demo shim: patches `window.fetch` with in-memory fixtures, runs a scripted timeline, mounts the "demo" badge. Plain browser JS, no bundler. |
| `demo/build.ts` | Copies `dist/` → `dist-demo/` and injects the shim's `<script>` tag. Run by `build:demo`. |
| `vite.config.ts` | Vite + Tailwind; in dev, proxies `/api` → `127.0.0.1:8444` (a running `honmoon gateway`). |

## Code Style

- React 19 + Vite + Tailwind 4. ESM, `strict: true`. Lint via `@pleaseai/eslint-config` with
  `eslint-plugin-react-hooks` / `react-refresh`.
- Light/dark aware: `color-scheme: light dark` plus the oklch tokens in `index.css`, switched by
  `@media (prefers-color-scheme: light)` — no Tailwind `dark:` variants. Keep the shell minimal —
  data density over decoration. Mirror clawpatrol's dashboard structure where it enables component reuse.

## Testing

`bun run test` (from this directory, or `bun run --filter '@honmoon/dashboard' test` from the
root) runs `bun test` over `src/**/*.test.tsx`. Tests register happy-dom themselves via
`@happy-dom/global-registrator` and drive React with `act` — no testing-library. Add
component/interaction tests alongside any real surface you build; `hooks.test.tsx` is the
pattern to copy. CI does not run this suite yet (`.github/workflows/ci.yml`).

## Boundaries

- ✅ **Always**: consume policy types from `@honmoon/policy`; keep the UI light/dark aware.
- ⚠️ **Ask first**: adding heavy UI dependencies; changing the embedding strategy (`rust-embed`).
- 🚫 **Never**: hardcode policy logic in the UI (the data plane decides); present scaffold
  surfaces as functional.
