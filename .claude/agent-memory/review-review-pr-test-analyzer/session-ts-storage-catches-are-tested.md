---
name: session-ts-storage-catches-are-tested
description: "apps/dashboard/src/session.ts has two independent storage try/catch branches (read() and write()) and PR #194 ended with a test for each — plus a shape-check test and a Rust test pinning the 64-hex secret contract; do not re-report any of them as untested, and never stub Storage by assignment (see the pattern below)"
metadata:
  type: project
---

`apps/dashboard/src/session.ts` holds the dashboard's management credential (issue #188: the
`honmoon_session` cookie was harvestable by any sibling `127.0.0.1` listener, so the secret moved
to origin-scoped `sessionStorage` sent as `X-Honmoon-Session`). Its storage access has two
separate failure branches, and both are covered as of PR #194 — **do not re-report either as an
untested error path**:

- `read()` (`sessionStorage.getItem` throws — a reload in a browser blocking site data) →
  `a browser that blocks reads reports no credential rather than throwing`. It matters because
  `api.ts` calls `sessionHeaders()` inside every `fetch`, so an escaping exception would break
  every call instead of taking the 401 "not signed in" path.
- `write()` (`setItem` throws) → `a browser that blocks writes keeps no credential and no secret
  in the URL`. It asserts both halves: no credential, **and** the fragment is still cleared from
  the address bar (keeping it would leave a live secret where a bookmark or a screenshot picks it
  up, to buy a retry that a still-blocked browser cannot complete).
- The fragment shape check → `a fragment that is not a 64-char hex secret is refused`, paired with
  `the_login_secret_is_64_hex_characters` in `crates/honmoon-mgmt/tests/e2e.rs` so the TS-side
  regex and the Rust-side derivation cannot drift silently.

Each was verified to fail when its own guard is removed, not merely to pass.

**How to apply — the stub that looks right and covers nothing.** happy-dom's `Storage` is a
`Proxy`: `sessionStorage.setItem = () => { throw }` is silently dropped and the real method still
runs, so a storage-failure test written that way exercises the ordinary path and passes for
implementations with opposite behaviour. PR #194's first draft had exactly that, and it passed
both before and after the behaviour changed. Use the file's `withBlockedStorage` helper
(`Object.defineProperty(sessionStorage, method, { value, configurable: true })`, restored in a
`finally`) and, for any new storage branch, confirm the test fails with the guard removed.
