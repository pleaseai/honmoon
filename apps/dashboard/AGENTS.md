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
# or from root:
bun run dashboard:dev
```

## Structure

| Path | What |
|------|------|
| `src/main.tsx` / `src/App.tsx` | Entry point; tab shell over the four views. |
| `src/components/` | `Overview`, `AuditLog`, `PolicyView`, `Approvals`, `DecisionBadge`. |
| `src/api.ts` / `src/hooks.ts` / `src/format.ts` | Typed management-API client, `usePolling`, formatters. |
| `vite.config.ts` | Vite + Tailwind; in dev, proxies `/api` → `127.0.0.1:8444` (a running `honmoon gateway`). |

## Code Style

- React 19 + Vite + Tailwind 4. ESM, `strict: true`. Lint via `@pleaseai/eslint-config` with
  `eslint-plugin-react-hooks` / `react-refresh`.
- Light/dark aware (`color-scheme` / Tailwind `dark:` variants). Keep the shell minimal — data
  density over decoration. Mirror clawpatrol's dashboard structure where it enables component reuse.

## Testing

No tests yet. Add component/interaction tests alongside any real surface you build.

## Boundaries

- ✅ **Always**: consume policy types from `@honmoon/policy`; keep the UI light/dark aware.
- ⚠️ **Ask first**: adding heavy UI dependencies; changing the embedding strategy (`rust-embed`).
- 🚫 **Never**: hardcode policy logic in the UI (the data plane decides); present scaffold
  surfaces as functional.
