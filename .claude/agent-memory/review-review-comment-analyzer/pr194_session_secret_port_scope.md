---
name: pr194-session-secret-port-scope
description: "PR #194 (issue #188) session-cookie-to-header migration comments — I reported this diff clean and MISSED a comment stating a false mechanism (SESSION_HEADER's \"lowercase or HeaderMap lookups fail\" rationale; HeaderMap::get normalises a mixed-case key, so the stated reason was untrue). A mechanism claim has to be executed, not read — how to check the ones in this file"
metadata:
  type: project
---

PR #194 replaced the `honmoon_session` cookie with an origin-scoped `sessionStorage`
secret sent as `X-Honmoon-Session`, and deleted `same_origin()` and the `Credential`
enum. This PR was comment-heavy by design (long rationale in
`crates/honmoon-mgmt/src/lib.rs` and `apps/dashboard/src/session.ts`), and every claim
checked out on verification:

- `authorized()`'s "neither credential is ambient" argument: both `Authorization` and
  `X-Honmoon-Session` are non-simple headers requiring a CORS preflight; the service has
  no CORS middleware at all (`grep -n cors` in lib.rs is empty), so a cross-origin
  preflight is never answered. No asymmetry between the two arms.
- `SESSION_HEADER`/`session_secret`/`login`/`require_credential` doc clauses (fragment
  never sent to a server, no `Referer` leak since the response is a redirect not a
  page's own URL, hex needs no escaping, `history.replaceState`) all matched the code
  and `apps/dashboard/src/session.ts`.
- `require_credential`'s cited test name
  `no_session_cookie_is_a_credential_so_a_sibling_port_has_nothing_to_harvest` exists in
  `crates/honmoon-mgmt/tests/e2e.rs:1037` and asserts the absence the comment claims.
- `FRAME_ANCESTORS_NONE`'s "fresh tab gets its own empty sessionStorage" claim is
  correct: sessionStorage is scoped per top-level browsing context (tab), not shared
  across tabs even same-origin.
- `session.ts` module doc's "nothing here renders API data as HTML" — verified via
  `grep -rn dangerouslySetInnerHTML|innerHTML` across `apps/dashboard/src/`: no hits.
- Wiki doc line-range citations (`lib.rs:459-488`, `531-580`, `393-436`) were checked
  against actual file line numbers post-diff and are accurate to the enclosing doc+fn
  block.
- No dangling references to the removed `same_origin`, `Credential`, `SESSION_COOKIE`,
  `session_cookie_value`, or removed cookie tests anywhere in the diff (grep across
  `*.rs *.ts *.tsx *.md` clean).

**What I missed, and the lesson that replaces the one this note first recorded.** I reported the
diff clean. It was not: `SESSION_HEADER`'s doc comment said it must be lowercase "because
`HeaderMap` lookups are case-insensitive only through the lowercase form the `http` crate
normalises to". That mechanism is false — `HeaderMap::get` normalises a `&str` key, so an
uppercase constant would have found the header perfectly well (measured with a throwaway test:
`h.insert("x-honmoon-session", …); h.get("X-Honmoon-Session").is_some()` → true). The real reason
is convention: lowercase is the on-the-wire form for HTTP/2 and HTTP/3 (RFC 9113 §8.2.1) and what
`http` stores. The comment now says that.

Why I missed it: I checked the claim for *internal coherence* and against the code's *behaviour*
(the header is found, the tests pass) — and both were consistent with the false reason, because
the code works either way. A claim of the form "X is required because otherwise Y breaks" is only
verified by making X false and seeing whether Y breaks. Reading cannot do it; a four-line
throwaway test can.

**How to apply:** in this file, the remaining load-bearing mechanism claims are `session_secret`'s
"fixed-width hex needs no escaping", `login`'s "a fragment is never sent to any server", and
`clearFragment`'s "`replaceState` throws in an opaque origin". Each asserts that something would
break otherwise — so each is verified by breaking it, not by reading it. And do not record "a
clean review is possible here" as a lesson: on this PR that conclusion was itself the error.
