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
  ],
}, {
  // Bun/Node entrypoints: `process` is a legitimate global; CLI/server log to stdout.
  files: ['packages/**/*.ts'],
  rules: {
    'node/prefer-global/process': 'off',
    'no-console': 'off',
  },
})
