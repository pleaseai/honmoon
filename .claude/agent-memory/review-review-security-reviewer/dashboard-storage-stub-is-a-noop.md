---
name: dashboard-storage-stub-is-a-noop
description: In apps/dashboard's happy-dom tests, assigning sessionStorage.setItem (or getItem) does NOT replace the method — Storage is a Proxy, the assignment is swallowed, and the real method still runs, so any "browser that blocks site data" test written that way is a false green
metadata:
  type: project
---

Measured in this repo (bun 1.4.2 + `@happy-dom/global-registrator`, `apps/dashboard/src`):

```ts
const original = sessionStorage.setItem.bind(sessionStorage)
sessionStorage.setItem = () => { throw new Error('blocked') }
sessionStorage.setItem('k', 'v')   // does NOT throw
sessionStorage.getItem('k')        // 'v'  — the real setItem ran
sessionStorage.getItem('setItem')  // null — the assignment vanished entirely
```

happy-dom's `Storage` is a `Proxy`; a property assignment is neither stored as an item nor
installed as an own property, so the method stays intact. Consequence: a test that stubs
`setItem`/`getItem` to throw in order to simulate blocked site data exercises the *normal*
path and passes whatever the fallback does — including passing for two implementations with
opposite behaviour. PR #194's first draft of
`apps/dashboard/src/session.test.ts` was exactly this shape, and it passed both before and after
the behaviour under test changed sign — which is how it was caught. It now injects the failure
with `Object.defineProperty` (the file's `withBlockedStorage` helper) and each storage branch was
confirmed to fail with its own guard removed.

**How to apply:** when reviewing or writing a test for a `try { sessionStorage… } catch`
branch in `session.ts` (the management credential — see [[mgmt-api-auth-model]]), require the
storage failure to be injected with `Object.defineProperty` on the storage object (measured
working), or by injecting the storage object itself — and require evidence that the test fails
when the guard is removed. Otherwise treat it as covering nothing.
