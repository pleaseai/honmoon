---
name: cel-compile-panic-class
description: cel-interpreter 0.10 Program::compile panics (antlr4rust unreachable!) on any lone character it cannot begin a token with — the measured set, why trim().is_empty() deliberately does not cover all of it, and why catch_unwind is not the fix
metadata:
  type: project
---

`cel_interpreter::Program::compile` (0.10, via `antlr4rust-0.3.0-rc2/src/tree.rs:383`) **panics**
rather than returning `Err` on a large class of input.

**The class, measured.** An earlier draft of this note said "any input that lexes to no tokens".
That is wrong and understates it — a second probe during PR #155's review found `Program::compile`
panics on *any lone character it cannot begin a token with*, which includes plenty that lex fine:
`"@"`, `"$"`, `"#"`, `` "`" ``, `";"`, `"§"`, `"€"`, an emoji, a lone CJK character, and the
invisible ones `"\u{200b}"`, `"\u{feff}"`, `"\u{2060}"`, `"\u{00ad}"`. Also `""`, whitespace,
`"// nothing"`, and the syntax errors #154 lists (`"&&"`, `")"`, `"'abc"`, `"."`, `"()"`,
`"true &&"`). `"x"` and `"_"` compile; so do `"\u{200b}true"` and `"\u{feff}true"` (they return
`Err`) — it is only the *lone* unlexable character that panics.

**Why `is_blank_condition` stops where it does.** `honmoon_core::is_blank_condition` (PR #155,
`crates/honmoon-core/src/lib.rs`) is `condition.trim().is_empty()`, i.e. Unicode `White_Space`. It
catches `U+0085` (NEL), `U+00A0` and `U+3000` but **not** `U+FEFF` or `U+200B`, so a condition
made only of those loads through `Policy::from_yaml` and panics in `decide` at request time. This
is a deliberate boundary, not an oversight: `U+200B` panics for the same reason `"@"` does, and
neither is whitespace, so a predicate that stripped zero-width characters would fix one arbitrary
slice of the set while reading as coverage. **Do not file or accept "just also strip zero-width
characters" — #155 considered and documented exactly that.** The whole class is #154.

The JSON Schema mirror uses ECMA `pattern: "\\S"`, whose `\s` *does* include `U+FEFF` but *not*
`U+0085` — so the two checks disagree in both directions, by one character each way. Both files
document this; nothing enforces it (see #157).

**How to apply.**

- Impact is bounded by [[policy-yaml-trust-boundary]] — policy text is author-controlled (file-only
  load, mgmt API is GET-only), so this is an availability/robustness gap, not an attacker-reachable
  DoS. Do not escalate it to high severity on an author-only path; do re-check it if a policy-write
  route ever appears.
- **Do not recommend `catch_unwind`.** An earlier draft of this note did. It is the first thing
  that comes to mind and it is explicitly rejected in #154 and in #155's review: it converts a
  panic into a *caught* panic rather than into a validated policy, and leaves `honmoon_core::Error`
  claiming a set of failures it cannot actually represent. Compiling at load is rejected for a
  related reason — it moves the panic to startup and makes `from_yaml`'s `Result` a lie. The fix
  belongs upstream (cel-rust / antlr4rust returning an error from the recovery path instead of
  hitting `unreachable!`) or in a move off the antlr-generated parser.
