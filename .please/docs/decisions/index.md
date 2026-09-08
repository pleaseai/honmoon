# Decisions Index

> Auto-maintained by /please:plan.

| ADR | Title | Date | Status |
|-----|-------|------|--------|
| [0001](0001-adopt-pingora-http-data-plane.md) | Adopt Pingora for the HTTP/HTTPS data plane | 2026-06-20 | Superseded by 0002 |
| [0002](0002-phase1-connect-proxy-on-tokio.md) | Phase 1 CONNECT egress proxy on raw tokio; defer Pingora | 2026-06-20 | Accepted |
| [0003](0003-adopt-hudsucker-for-tls-termination.md) | Adopt hudsucker for TLS termination (MITM) in the data plane | 2026-07-02 | Accepted |
| [0004](0004-unprivileged-userns-tun-for-honmoon-run.md) | Enforce `honmoon run` isolation with an unprivileged user namespace + TUN | 2026-08-28 | Superseded by 0005 |
| [0005](0005-empty-namespace-and-bridged-proxy-sockets.md) | Confine `honmoon run` with an empty namespace and bridged proxy sockets | 2026-08-28 | Accepted |
| [0006](0006-signed-body-requests-under-wire-redaction.md) | Body-signed requests under wire redaction | 2026-09-07 | Accepted |
| [0007](0007-inline-postgresql-runtime-semantics.md) | Inline PostgreSQL runtime semantics | 2026-09-08 | Accepted |
