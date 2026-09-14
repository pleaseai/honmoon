---
name: hook-salt-adoption-contract-pr242
description: "PR #242 (issue #126 stage 1) pins load_or_create_machine_salt's adoption contract in hook.rs with 4 new tests; a_salt_at_exactly_the_sixteen_byte_floor_is_adopted_verbatim's doc comment names the 4 pre-existing tests covering the rest of the boundary — verified all 8 claims true, no gap, no weak assertion, no tag collision"
metadata:
  type: project
---

PR #242 is doc/test-only (no production behaviour change) pinning the hook-salt
adoption contract: a `~/.honmoon/hook-salt` file of >= 16 bytes is adopted
verbatim at whatever length it has; shorter/unreadable/absent mints a fresh
32-byte key; adoption restricts the file to 0600 where it can and records a
`hook-salt-exposed` audit event where the file stays readable beyond its owner.

Verified by reading each test body (not just names):
- `a_salt_at_exactly_the_sixteen_byte_floor_is_adopted_verbatim` (16B floor)
- `a_salt_one_byte_under_the_floor_is_regenerated` (15B, the floor's other side)
- `a_salt_longer_than_a_generated_key_is_adopted_whole` (64B, no ceiling/no
  truncation to the loader's own 32B output length)
- `salt_dirs_holding_the_same_bytes_derive_the_same_session_salt` (parity
  invariant the README's "Getting one key onto both sides" section rests on;
  has a differing-bytes negative control so a constant-return loader would
  fail it)

Two doc comments carry the citations, and they are not interchangeable: the
rustdoc on `load_or_create_machine_salt` names the four *new* tests above, while
`a_salt_at_exactly_the_sixteen_byte_floor_is_adopted_verbatim`'s own doc comment is
where the four *pre-existing* tests are named as covering the rest of the boundary
(absent/short/unreadable file, 0600 re-tightening): `machine_salt_persists_and_is_stable`,
`machine_salt_regenerates_short_or_corrupt_file`,
`a_replaced_file_that_was_owner_only_is_recorded_as_such`,
`machine_salt_read_path_retightens_loose_permissions`. Read all four —
each claim held. No coverage gap, no weak assertion (each length/byte-content
check would fail under truncation, hashing, or constant-return mutants), and
all `TempDir::new(tag)` tags across the whole file (~35 tests) are unique, so
no test-isolation risk.

An empty (0-byte) hook-salt file is not a separately-coded branch — it falls
into the same `Ok(bytes) if bytes.len() >= 16` / else arm as any other
short file, so it needs no dedicated test beyond the existing short-file cases.

See also [[docs-completeness-claim-unbounded-review]] (top-level memory) —
this PR's doc comments made bounded, falsifiable claims (named specific
tests) rather than unbounded ones, which is why verifying them cost one pass
over 4 tests rather than opening every review round to a fresh claim.
