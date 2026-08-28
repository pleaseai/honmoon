# ADR-0004: Enforce `honmoon run` isolation with an unprivileged user namespace + TUN

## Status

Accepted

## Context

`honmoon run` (`crates/honmoon-cli/src/main.rs`) starts an ephemeral egress proxy and points the
child at it with `http_proxy` / `https_proxy` / `all_proxy` (and their uppercase spellings). That is
**advisory**: a child that ignores those variables — a Go binary using its own dialer, a `curl
--noproxy '*'`, anything with a hardcoded socket — bypasses policy entirely. **TD-003** rates this
High, and it undercuts the product's core promise: a firewall an agent cannot route around.

Enforcement has to come from the OS, not from the child's cooperation. Three shapes were
considered for Linux:

- **root + veth pair with default-deny.** The obvious reading of "network namespace". Creating a
  veth pair and moving one end into the host namespace requires `CAP_NET_ADMIN` **in the initial
  namespace**, i.e. real root. For a tool whose primary use is wrapping a local coding agent,
  requiring `sudo` on every invocation is a severe usability regression.
- **Unprivileged user namespace + an external userspace network stack** (`slirp4netns`, `passt` /
  `pasta`). No root, but adds a runtime dependency on a binary we do not ship, contradicting the
  single-binary deployment property in `tech-stack.md`.
- **Unprivileged user namespace + a TUN device, with the userspace TCP/IP stack in-process.** No
  root, no external binary. The child's namespace contains exactly one network device — a TUN whose
  other end we hold — so there is no path out except through our stack.

### Prior art

`denoland/clawpatrol` ("security firewall for agents", MIT) ships the third shape, and its
`cmd/clawpatrol/run_linux.go` was read directly rather than taken from summary:

- re-execs itself with `CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS` and a 1:1 uid map (L201-L206)
- grants the re-exec'd child `AmbientCaps: [CAP_NET_ADMIN, CAP_SYS_ADMIN]` (L216) — capabilities
  **inside the new user namespace**, which is why no host root is needed. `CAP_NET_ADMIN` covers
  `TUNSETIFF` (L795) and the interface/route setup; `CAP_SYS_ADMIN` covers the `resolv.conf`
  bind-mount in the new mount namespace
- passes the TUN file descriptor back to the parent over `SCM_RIGHTS`, where a userspace network
  stack (gVisor netstack, Go-only) and a TCP forwarder terminate it
- calls `clearAmbientCaps()` (L454, L648) **before** exec'ing the user's command, so the wrapped
  agent never holds `CAP_NET_ADMIN` and cannot reconfigure its own namespace

The critical insight is that **no veth is required**. A TUN device created *inside* the new
namespace, with its fd handed outward, needs no privilege over host networking at all.

### Rust equivalent of the userspace stack

gVisor netstack has no Rust counterpart. `tun2proxy` (crates.io `0.8.3`, MIT) is a closer fit than a
raw stack: it terminates a TUN device and forwards TCP to an **HTTP proxy** — which is exactly what
`honmoon run` already has listening. Its library entry point is
`run<D>(device: D, mtu: u16, args: Args, shutdown_token: CancellationToken)`, generic over the
device, and the binary exposes `--tun-fd`, so a descriptor we created ourselves can be adopted.
`smoltcp` remains the fallback if `tun2proxy`'s abstraction proves too rigid.

`tun2proxy` also ships `--unshare [ADMIN_COMMAND]`, which performs a similar namespace dance
itself. We do **not** use that path: it runs the wrapped command with root-like capabilities inside
the namespace, where we want the opposite — capabilities dropped before the agent starts.

### macOS

`clawpatrol` uses a `NETransparentProxyProvider` shipped as a **signed system extension** inside
`Clawpatrol.app`, with `clawpatrol install` triggering the one-time approval prompt
(`macos/ClawpatrolExtension/Provider.swift`, `cmd/clawpatrol/run_darwin.go:31`). That requires
Apple Developer Program membership, signing, and notarization. The organization has that
membership, so this is a cost question rather than a blocker — but a Swift system extension plus a
container app is a separate body of work from the Linux data path, and is split into its own issue.

## Decision

Implement enforced isolation for `honmoon run` on **Linux** as:

1. Re-exec `honmoon` into new user, network, and mount namespaces with a 1:1 uid map and ambient
   `CAP_NET_ADMIN` + `CAP_SYS_ADMIN`.
2. Create a TUN device inside that namespace, configure the interface and a default route over it,
   and bind-mount a `resolv.conf` pointing at a resolver reachable through the tunnel.
3. Pass the TUN descriptor to the parent over `SCM_RIGHTS`.
4. In the parent, drive the descriptor with `tun2proxy` as a **library**, targeting the ephemeral
   honmoon CONNECT proxy already bound by `run`.
5. Clear the ambient capability set before `exec`ing the user's command, so the wrapped agent holds
   no capability over its own namespace.

Use `tun2proxy` as a dependency, not the `tun2proxy-bin` binary — the single-binary deployment
property is preserved.

**macOS is out of scope here.** `honmoon run` on macOS keeps the environment-variable path and says
so explicitly; the `NETransparentProxyProvider` extension is tracked separately.

**Behavior when isolation is unavailable is fail-open**: warn on stderr and run the child with the
proxy environment variables only. This matches `clawpatrol`, which prints
`⚠ session register: … (proceeding without tunnel)` and proceeds (`run_darwin.go:43-48`).

## Consequences

- `honmoon run` becomes genuinely enforcing on Linux: the child's namespace has one device and no
  route around it, so ignoring `https_proxy` fails rather than escapes.
- No `sudo`, no external helper binary, no change to how the proxy or policy engine work — the
  isolation layer sits entirely in `honmoon-cli` and feeds the existing CONNECT proxy.
- Unprivileged user namespaces must be enabled in the kernel. Where they are not (some hardened
  distributions, certain container runtimes), isolation is unavailable and the fail-open path
  applies.
- Fail-open means a misconfigured host silently degrades to advisory enforcement. The warning is the
  only signal, and it is easy to miss in agent output. Revisiting this posture — or gating it behind
  an explicit flag — is a reasonable follow-up once the Linux path has real usage.
- UDP and DNS need deliberate handling: the CONNECT proxy carries TCP only, so DNS has to be
  resolved through the tunnel or pinned to a resolver reachable across it.
- A second platform-specific code path enters `honmoon-cli`, which until now was portable.
