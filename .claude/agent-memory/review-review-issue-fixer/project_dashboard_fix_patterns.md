---
name: dashboard-fix-patterns
description: Honmoon dashboard fix constraints — @honmoon/policy value imports resolve, eslint import-style rule, oklch contrast math
metadata:
  type: project
---

Fixing review findings in `apps/dashboard`:

- **Value imports from `@honmoon/policy` build fine.** Its package.json `exports` points at raw
  `./src/index.ts`, so Vite transpiles it directly — no dist build step needed. A finding that says
  "skip if the value import cannot resolve" can be answered with a `build` run, not guessed.
  **Why:** several dashboard files use `import type` only, which is erased and proves nothing at
  typecheck time. **How to apply:** only `bun run --filter '@honmoon/dashboard' build` is evidence.
- **eslint enforces `import/consistent-type-specifier-style`.** Inline `type` specifiers mixed into
  a value import (`import { X, type Y }`) error out; it must be split into a separate
  `import type { Y }` line. **Why:** repo lint config. **How to apply:** when a finding literally
  prescribes the inline form, apply it then run `bunx eslint --fix` on that file.
- **Contrast findings cite oklch tokens in `src/index.css`.** Composite translucent surfaces in
  gamma-encoded sRGB (not linear) or the ratio comes out optimistic. Real backdrops nest
  `--surface-soft` over `--surface-glass` over `--bg`, which is worse than the two-layer case a
  finding usually quotes — check the three-layer stack too.
