---
name: project-audit-sink-macos-acl-181
description: 'PR #213 (issue #181) — the audit sink''s trusted-directory rule now reads a macOS extended ACL via hand-declared libSystem externs (libc has no acl_* on Apple); measured platform facts so they are not re-derived, the three-way cfg split and why the Linux arm is narrowed to POSIX.1e (#215), and the macOS CI job widening that makes the tests run at all'
metadata:
  type: project
---

`crates/honmoon-core/src/audit.rs::require_link_in_a_trusted_directory` (PR #213, closing #181)
gained a second test beside the `uid`/`mode & 0o022` one. Before it, a macOS NFSv4-style ACL set
with `chmod +a` made a root-owned `0755` directory read as trusted, and a symlink planted in it
was followed — the #160 hole, re-opened by a mechanism `st_mode` cannot show.

**Measured on Darwin 24, not inferred.** Re-deriving these costs a C harness; they were checked
with one:

- `chmod +a "<who> allow write,file_inherit,directory_inherit"` on a `0755` dir leaves
  `st_mode` at `40755`, before and after. The issue's premise is exact.
- `acl_get_fd_np(fd, ACL_TYPE_EXTENDED)` returns NULL with `errno == ENOENT` when there is no
  ACL — `ENOENT`, not `ENOATTR`. Non-null for any ACL, **including a deny-only one**.
- It answers an `O_SEARCH` descriptor (the `O_TRAVERSE` retry in `open_directory`) as readily as
  a readable one. Pinned by `an_extended_acl_is_visible_through_a_search_only_descriptor`.
- The `fgetxattr(KAUTH_FILESEC_XATTR)` route is **dead** — current macOS returns `EPERM`, not the
  ACL blob. Do not propose it as the dependency-free alternative; it was tried.
- `/`, `/private/var`, `/private/tmp` and `/var/log` carry no ACL as macOS ships them, so
  `/var -> private/var` and the default `TMPDIR` under it still resolve. **`$HOME` does** —
  `group:everyone deny delete`, on every macOS home directory.

**The rule tests for an ACL's presence, not its contents, and that is deliberate.** Reading which
entries grant write means `acl_get_entry`/`acl_get_tag_type` plus a permset, and a misread there
fails open — the direction #181 already went once. The cost is the `$HOME` case above: a symlink
held *directly* in a home directory is refused with nothing wrong. That is documented in
`carries_an_extended_acl` and pinned by `with_file_refuses_a_symlinked_parent_whose_acl_only_denies`,
which exists so an inverted allow/deny refinement fails a test instead of shipping. A reviewer
proposing deny-only-is-trusted is proposing something sound, not catching a gap — answer it on
whether the extra FFI is worth the narrower refusal, not as a defect.

**No new dependency, and `crate_boundary.rs` is silent by design.** `libc` carries no `acl_*` on
Apple targets, so `audit.rs` declares `acl_get_fd_np` and `acl_free` itself in an
`unsafe extern "C"` block. Both live in `libSystem`, which `std` already links there — the
manifest does not move, so the boundary test cannot see it, and `crates/AGENTS.md` names the pair
explicitly for that reason. A *further* hand-declared system symbol is a new decision; this
precedent does not grant it.

**Three `cfg` arms, matching the `O_TRAVERSE` shape a few lines above.** macOS reads the ACL;
Linux answers `false`; **any other Unix answers `true`**. The middle arm's justification is
POSIX.1e's — the ACL mask *is* `st_mode`'s group bits, so `0o020` already bounds every
`ACL_USER`/`ACL_GROUP` grant — and it is Linux-specific: FreeBSD and illumos carry NFSv4 ACLs with
the same blindness, which is why they fail closed rather than share the Linux arm. Linux itself can
present a non-POSIX.1e ACL (NFS mount, OpenZFS `acltype=nfsv4`); that residual is **issue #215**,
left open because reading it needs `getxattr` of `system.nfs4_acl` on a filesystem neither CI job
mounts, and an untested security control is what the CI change below exists to prevent.

**`.github/workflows/ci.yml`: the macOS job now runs `-p honmoon-cli -p honmoon-core`**, renamed
`Rust — macOS-only code paths`. It ran `honmoon-cli` alone on the premise that the rest of the
workspace is platform-neutral; `honmoon-core` now has `cfg(target_os = "macos")` code, so the new
tests would have compiled everywhere and executed nowhere. **A third crate growing a macOS cfg
belongs on that list too.** Note `codecov/patch` goes red on any macOS-only diff — the coverage
job is ubuntu-only, so those lines read as unhit and cannot be covered from there; it is not a
gate (`main` requires no status checks) and not something to chase.
