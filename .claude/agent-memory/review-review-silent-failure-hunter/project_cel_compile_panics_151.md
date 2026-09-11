---
name: project-cel-compile-panics-151
description: honmoon-core rule conditions — Program::compile panics on a whole class of malformed CEL instead of returning Err, so compile_condition's Err arm is not the full failure mode; blank is handled (PR #155), the rest is open (#154)
metadata:
  type: project
---

`crates/honmoon-core/src/engine.rs::compile_condition` matches `Ok`/`Err` on
`cel_interpreter::Program::compile` and documents `Err` as the failure it degrades on. That is a
true statement about the code and an incomplete statement about the compiler: `compile` does not
return at all on some malformed input — it panics inside antlr's error recovery
(`antlr4rust-0.3.0-rc2/src/tree.rs:383`, `unreachable code: should have been properly implemented
by generated context when reachable`).

Measured on cel-interpreter 0.10.0 / cel-parser 0.10.1 (PR #155, 22 inputs under `catch_unwind`).
**12 panic**: `""`, `" "`, `"\n"`, `"\t\r\n"`, `"// nothing"`, `")"`, `"&&"`, `"true &&"`,
`"'abc"`, `"."`, `"()"`, `";"`. **5 return `Err`**: `"(true"`, `"== 1"`, `"a..b"`, `"a[]"`, `"?"`.
**5 return `Ok`**: `"true"`, `"1"`, `"'x'"`, `"{}"`, `"nope.field == 1"` — the last three compile
and simply never evaluate to `Bool(true)`, which is the ordinary no-match path, not a failure.

Which syntax errors land on the panic is an antlr recovery-path property, so the call site cannot
predict it from the input's shape.

**The class is wider than "malformed CEL", and this is the part that changes review advice.** A
second probe during #155's review found that `Program::compile` panics on *any single character it
cannot begin a token with*: `"@"`, `"$"`, `"#"`, `` "`" ``, `"§"`, `"€"`, an emoji, a lone CJK
character — and, invisibly, `"\u200b"`, `"\ufeff"`, `"\u2060"`, `"\u00ad"`. `"x"` and `"_"`
compile. So the panicking set is not a list of typos; it is most of the character space.

That is why #155 did **not** extend the blank check to cover zero-width characters even though a
condition made only of them looks empty in an editor and reproduces the exact #151 crash: they
panic for the same reason `"@"` does, and neither is whitespace. Folding them in would fix an
arbitrary slice and read as coverage. If a future reviewer proposes it, this is the answer.

**What is closed.** PR #155 handles the blank class at both ends: `Policy::validate_rules` rejects
a rule whose `condition` is blank at load (`Error::BlankRuleCondition`), and `compile_condition`
declines a blank condition before reaching the compiler — the second guard is for a `Policy` built
in code, since `decide` takes any `&Policy` and the struct is public and `Deserialize`. Both read
`is_blank_condition`, so the two cannot drift.

**What is open (#154).** Everything else in the panic list, including the invisible-character case
above. A policy with `condition: "&&"` — or with a condition that is one zero-width space — still
loads cleanly and crashes the decision path at request time.

**How to apply.** Two things to check on this code path:

1. Do not accept "a condition that fails to compile simply does not match" as a complete account
   of the failure modes, in prose or in a doc comment. It covers the `Err` arm only. A panic is
   not a failure this crate degrades on; it is an availability bug in a firewall.
2. Do not propose the three obvious fixes without reading #154 first — each was considered and
   rejected there with reasons. Compiling at load moves the panic to startup and makes
   `from_yaml`'s `Result` a lie; `catch_unwind` produces a caught panic rather than a validated
   policy and leaves `honmoon_core::Error` claiming failures it cannot represent; a syntactic
   pre-check that separates `")"` from valid CEL is a CEL parser. The fix most likely belongs
   upstream.
