---
name: cel-compile-panic-class
description: "The CEL compile-panic class (#154) is CLOSED — honmoon moved to `cel` 0.14, whose Program::compile returns Err for the whole set that used to panic (`@`, `§`, emoji, lone zero-width, `&&`); that it is still the antlr4rust parser and NOT the feature-gated Pratt one, why is_blank_condition still exists, why catch_unwind is still never the fix, and the default parser's only parse limit (recursion 96)"
metadata:
  type: project
---

**Status: closed.** `crates/honmoon-core/Cargo.toml` pins `cel = "0.14"` (lockfile 0.14.5), and
`cel::Program::compile` returns `Err(ParseErrors)` for the whole class that panicked under
`cel-interpreter` 0.10: `""`, whitespace, `"&&"`, `")"`, `"."`, `"@"`, `"§"`, emoji, lone
`U+200B`/`U+FEFF`. Do **not** file a panic/DoS finding citing #154 against current code — verify
the pinned version first (see [[cargo-lock-not-registry-cache]]).

**It is still antlr, and that matters for which limits apply.** `Program::compile` calls
`Parser::default()`, which is `cel-0.14.5/src/parser/parser.rs` — the antlr4rust-generated
`gen::CELLexer` / `gen::CELParser` path (antlr4rust 0.5.2). The hand-written Pratt parser in
`src/parser/pratt_parser.rs` is behind the `parser_pratt` feature, and `cel`'s default features are
`["regex", "chrono"]`, so honmoon does not build it at all. PR #164 said the same thing and it is
easy to get backwards, because the fix that closed #154 landed in antlr's error recovery rather
than by replacing the parser. Read a limit off `pratt_parser.rs` and you are reading a file this
build does not compile.

**What survives the version bump.**

- `honmoon_core::is_blank_condition` (`crates/honmoon-core/src/lib.rs`, `condition.trim().is_empty()`)
  stays, and its doc comment says why: blank is the authoring slip worth its own load error
  (`Error::BlankRuleCondition` from `validate_rules`), not a crash guard. Widening it to chase
  zero-width characters is still the wrong finding — the compiler now draws that line itself.
- `catch_unwind` is still never the recommendation.
- `Program` is `struct Program { expression: Expression }` with `execute(&self, &Context)` and no
  interior mutability, so one `Arc<Program>` is safe to share across threads and to re-execute
  (honmoon does exactly that for the `pii_caused` attribution re-run).
- Parse limits on the parser honmoon actually builds (`parser.rs`): `max_recursion_depth: 96`
  only, so the stack is bounded. There is **no** node-count limit on this path —
  `max_expression_node_count` is a `pratt_parser.rs` field and does not exist on
  `Parser::default()`, so expression size is bounded only by input length. honmoon configures
  neither and does not need to while [[policy-yaml-trust-boundary]] holds — policy text is
  author-controlled, file-only.

**Compiling at load is now the shipped design** (#167, PR #193): `Policy::from_yaml` fills the
private `compiled` table — see [[policy-compiled-conditions-table]]. An earlier version of this
note recorded "compiling at load is rejected because it moves the panic to startup"; that reason
died with the panic class.
