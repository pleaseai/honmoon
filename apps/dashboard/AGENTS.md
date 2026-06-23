# AGENTS.md — Dashboard (`apps/dashboard/`)

The Honmoon management dashboard: a React + Vite + Tailwind SPA. **Scaffold today** — `App.tsx`
renders a header, a static nav, and a placeholder body. The real surfaces (audit log viewer,
policy editor, approval queue) are Phase 4. Planned to be embedded into the Rust binary via
`rust-embed` and served by `@honmoon/api`.

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
| `src/main.tsx` | React entry point. |
| `src/App.tsx` | App shell (nav: Overview · Audit Log · Policies · Approvals — placeholder body). |
| `vite.config.ts` | Vite + Tailwind config. |
| `tsconfig*.json` | Strict TypeScript config. |

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
