---
name: main-rs-gateway-untestable
description: 'crates/honmoon-cli/src/main.rs::gateway() binds real sockets and blocks forever, so it has no unit test — wiring calls made directly inside it (rather than extracted like hook_salt_for) are never exercised even when the helpers they call are well-tested elsewhere; filed as #139'
metadata:
  type: project
---

`gateway()` in `crates/honmoon-cli/src/main.rs` binds `TcpListener`s and runs a
tokio runtime that blocks forever serving traffic, so nothing in the repo calls
it in a test. The project's existing pattern for this (see `hook_salt_for`,
tested by `an_unpinned_context_selects_the_per_session_salt`) is to pull
branch-worthy decisions out into small pure functions that *are* unit tested,
then call them from `gateway()`.

When a new call is added directly inside `gateway()` without such an
extraction — e.g. issue #131's
`hook::record_machine_key_source(&audit, honmoon_core::RedactionTransport::Gateway, &key_source)`
— it is invisible to the test suite: a typo swapping `RedactionTransport::Gateway` for
`RedactionTransport::Hook` there would not fail anything. Note precisely what is
and is not covered: `record_machine_key_source` is directly tested with *both*
transports — `the_gateway_transport_is_recorded_distinctly_from_the_hook`
(`hook.rs:971`) pins the Gateway value itself — but no test reaches the call
inside `gateway()`, so none of them can catch a wrong argument passed there. The
gap is the call site, not the helper's transport coverage. `key_source` comes
from `MachineKey::into_parts()`, which returns `(Vec<u8>, MachineKeySource)` —
the fields are private, so there is no `machine_key.source` to read.

**How to apply:** when reviewing a PR that adds a call inside `gateway()`,
check whether the call is a bare wiring statement (untestable in place) vs.
logic that could be extracted into a pure, named, testable helper the way
`hook_salt_for` was. Flag the former as a coverage gap rather than assuming
"it's in `main.rs` so it's exempt."
