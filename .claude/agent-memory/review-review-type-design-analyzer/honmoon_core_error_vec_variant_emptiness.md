---
name: honmoon-core-error-vec-variant-emptiness
description: "honmoon-core Error variants carrying a Vec (UncompilableRuleConditions.rules) are publicly constructible empty, rendering an empty Display; raised on PR #197 and DECLINED with reasons — do not re-raise for this variant, and read the reasons before raising it for a new one"
metadata:
  type: project
---

`crates/honmoon-core/src/lib.rs`'s `Error` enum (PR #197, issue #191) added
`UncompilableRuleConditions { rules: Vec<UncompilableRule> }`, whose
`#[error(...)]` attribute joins `rules` with `"; "`. Both the enum and the
variant's field are public, and `UncompilableRule`'s own fields are public
with no smart constructor — so `Error::UncompilableRuleConditions { rules:
vec![] }` compiles from any crate that depends on honmoon-core, and its
`Display` renders as an empty string.

**Why:** the only in-crate construction site
(`Policy::validate_compiled_conditions`) guards non-emptiness before
constructing the variant, so nothing today reaches the empty case — but the
guard lives at the call site, not the type. This is the classic "invalid
state representable" gap: the type's own shape doesn't rule out a
meaningless instance.

**Raised on PR #197 and declined.** The reasons, so this is not re-litigated
every round:

- Every variant of this enum has public fields, because enum variant fields
  are public whenever the enum is. `BlankRuleCondition { index, name }` can be
  constructed with an index that names no rule, and
  `DuplicateEndpointTarget` with a port that matches neither endpoint. An
  empty `rules` is the same class of nonsense, not a new one — so "the guard
  lives at the call site, not the type" describes the whole enum, and singling
  out the one `Vec` variant would be arbitrary.
- The suggested fixes (private field + smart constructor, or a non-empty
  newtype) add a type to prevent a state no code creates, against the
  repository's minimal-code standard. A `debug_assert!` in `Display` has the
  same problem in miniature.
- `Error` is a diagnostic payload, not a domain type carrying an invariant
  anything depends on. The cost of the empty case is one unhelpful message, in
  a variant only `validate_compiled_conditions` constructs.

**How to apply:** do **not** re-raise this for `UncompilableRuleConditions`.
For a *new* `Vec`-carrying variant, weigh it against the three points above
rather than flagging on shape alone — the finding is only worth making if the
variant is constructed somewhere that does not guard, or if the empty
rendering would be mistaken for success rather than merely unhelpful.

Compare against the crate's other single-cause variants
(`BlankRuleCondition`, `DuplicateEndpointTarget`), which carry no `Vec` and
don't have this shape — so this is a new pattern introduced by
`UncompilableRuleConditions`, not a preexisting one to re-flag elsewhere.
