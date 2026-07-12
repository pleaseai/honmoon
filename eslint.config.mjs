import pleaseai from '@pleaseai/eslint-config'

// PassionFactory standard ESLint config (wraps @antfu/eslint-config).
// See Skill("standards:dev-tooling") → references/code-style.md
//
// Scope: the JS/TS world. Rust and TOML are owned by `cargo fmt` / Cargo
// conventions, so they are ignored here.
export default pleaseai({
  react: true,
  typescript: true,
  ignores: [
    'target',
    '**/dist',
    '.please/**',
    'crates/**',
    '**/*.toml',
    // Generated VitePress docs site — self-contained sub-project with its own
    // toolchain (not a root workspace); its theme uses Vue/VitePress composables
    // that conflict with the app's React lint rules.
    'wiki/**',
  ],
}, {
  // Bun/Node entrypoints: `process` is a legitimate global; CLI/server log to stdout.
  files: ['packages/**/*.ts', 'datasets/**/*.ts'],
  rules: {
    'node/prefer-global/process': 'off',
    'no-console': 'off',
  },
}, {
  // apps/web is a faithful port of an approved single-file design. Two purely
  // stylistic rules fight that fidelity goal and are relaxed here only:
  //  - jsx-one-expression-per-line: the design uses dense inline markup; its
  //    autofix would reflow inline text around elements and shift rendered
  //    whitespace, breaking the "reproduce as-is" contract.
  //  - max-statements-per-line: the membrane canvas hook mirrors the original
  //    imperative draw loop line-for-line for auditability against the source.
  files: ['apps/web/**/*.{ts,tsx}'],
  rules: {
    'style/jsx-one-expression-per-line': 'off',
    'style/max-statements-per-line': 'off',
  },
})
