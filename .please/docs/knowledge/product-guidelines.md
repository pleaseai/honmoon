# Product Guidelines

> Branding, voice, UX, and engineering-style conventions for Honmoon.

## Naming & branding

- Product name: **Honmoon** (capitalized in prose). The CLI binary is `honmoon` (lowercase).
- Control-plane CLI binary: `honmoonctl`.
- npm scope: `@honmoon/*`. Rust crates: `honmoon-*`.
- One-line positioning: "A policy-based firewall gateway guarding the boundary between AI agents and production systems."

## Voice & docs

- Public-facing docs (README, `docs/`) are written in **English**.
- Be precise and grounded — this is a security tool; never overstate guarantees.
  Distinguish clearly between what is implemented vs. planned (use "target interface" / roadmap framing).
- Prefer tables and short code examples over long prose.

## Trust principles (non-negotiable)

- **Auditability is a feature.** The data plane — anything that inspects traffic or
  credentials — stays 100% open source. Never gate it behind a paywall.
- **Fail closed.** Default egress verdict is `deny`. Absence of a matching rule must not
  silently allow.
- **No decryption surprises.** Extract protocol facts at the wire level; document any
  inspection clearly.

## UX (dashboard)

- React + Vite + Tailwind SPA, embedded into the Rust binary via `rust-embed`, served by the
  management API. Mirror clawpatrol's dashboard structure where it lets us reuse components.
- Core surfaces: audit log viewer, policy editor (with syntax highlighting), approval queue.
- Light/dark aware (`color-scheme`). Keep the shell minimal; data density over decoration.

## Engineering style

- **Rust** (data plane): edition 2024, `rustfmt` + `clippy` clean. Errors via `thiserror`
  (libraries) / `anyhow` (binary). Keep `honmoon-core` transport-agnostic.
- **TypeScript** (control plane + dashboard): Bun runtime, `strict` true,
  `verbatimModuleSyntax`. ESM only.
- Keep the Rust `honmoon-core` policy model and TS `@honmoon/policy` in sync (see TD-001).
- Match surrounding code's conventions; do not introduce new abstractions speculatively (YAGNI).
