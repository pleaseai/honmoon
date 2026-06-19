# Honmoon Business Model

> Status: Draft (v0.1) · Author: Minsu Lee (@amondnet)

Honmoon follows an **Open Core** model.
The data plane (the firewall core) is fully open source to build trust and adoption,
while the control/cloud plane for teams and enterprises is monetized.

---

## 1. Core principle

> **The data plane is 100% open source. Monetization happens in the control/cloud plane.**

For a security tool, open source is not optional — it is nearly mandatory. Security teams
will not trust a "black-box proxy" that inspects their traffic and credentials.
**Auditability is itself a feature.** Locking the traffic-inspecting components behind a
paywall breaks trust and prevents adoption from happening at all.

This is also why the reference projects are all open source.

- [denoland/clawpatrol](https://github.com/denoland/clawpatrol) (Deno)
- [github/gh-aw-firewall](https://github.com/github/gh-aw-firewall) (GitHub)

Success hinges on **how generously and strongly the free core is built**.
The stronger the free core, the better the paid management plane sells.
Hold back the core, and both fail.

---

## 2. Free / paid boundary

The natural monetization boundary is the moment a user **moves from a single node to
operating a team/fleet**. The firewall itself must be powerful for free on a single node;
the problems that arise when running many agents, nodes, and people are the paid surface.

| Area | Open source (adoption & trust) | Paid (team & enterprise) |
|------|--------------------------------|--------------------------|
| Data plane | `crates/*` — proxy, protocol parsers, CEL engine, all of it | — (never locked) |
| Policy | YAML / local policy, single node | Fleet-wide central policy management, policy versioning, rollout & approval |
| Audit | Local audit log, self-hosted dashboard | Long-term retention & search, compliance reports (exfil / SOC 2) |
| Approval workflow | Basic `pause` verdict | Approval routing, Slack notifications, RBAC / SSO / SAML |
| Operations | Self-host | Hosted (SaaS) management plane, multi-tenancy, SLA / support |
| Intelligence | — | Managed allowlists, threat feeds |

### Monorepo mapping

The current monorepo layout already lines up with this boundary.

```
crates/                # Data plane — OSS (Apache-2.0)
packages/policy        # Policy model — OSS
packages/cli           # CLI — OSS
packages/api           # Control-plane API — OSS (base) / some paid features split out
apps/dashboard         # Dashboard — OSS
packages/enterprise/   # (planned) enterprise features — commercial license
apps/cloud/            # (planned) hosted SaaS management plane — private/commercial
```

---

## 3. Licensing strategy

| Target | License | Rationale |
|--------|---------|-----------|
| Core (`crates/*`, OSS packages) | **Apache-2.0** | Includes a patent grant, favorable for contribution & trust. Preferred over plain MIT. |
| Enterprise/cloud (`packages/enterprise`, `apps/cloud`) | **BSL or FSL** | Source-available but blocks competitors from re-hosting as SaaS — fits the *OSS + paid SaaS* goal exactly. |

- **FSL (Functional Source License) / BSL (Business Source License)**: used by Sentry,
  HashiCorp, and CockroachDB. Source-available licenses that convert to open source
  (Apache/MIT) after a set period.
- ⚠️ The current scaffold pins `MIT` in `Cargo.toml`. If open core is confirmed, this
  needs to change to **Apache-2.0 + a separated enterprise directory**.

---

## 4. Differentiation (the moat)

Competitors are Deno and GitHub, with **overwhelming distribution**. A simple domain
allowlist cannot win against them. Honmoon's moat must be the following combination:

1. **Protocol awareness** — parse SQL/K8s/HTTP at the wire level for fine-grained policy
   (going beyond a plain egress filter)
2. **Multi-runtime + self-host** — not tied to any single platform
3. **Unification** — egress domain filtering + protocol policy in one product

> The fact that this "wire-level core" cannot run on isolate environments like
> Cloudflare Workers actually creates value for host/container self-hosting.
> (See: Cloudflare deployment review — the wire-level core requires a host/container.)

---

## 5. Monetization timing

- **Individual developers do not pay for security tools.** Early on, focus solely on OSS adoption.
- **The buyer is the platform/security team**, and what they buy is "team-level management,
  compliance, and approval."
- Design so paid conversion **follows naturally once a team starts operating multiple agents**.

### Phased strategy

| Phase | Goal | Metric |
|-------|------|--------|
| 1. Adoption | Strong OSS core, easy install | GitHub stars, installs, active nodes |
| 2. Team entry | Surface friction points of multi-node operation | Team-level self-host cases |
| 3. Monetization | Hosted management plane + enterprise features | Paying teams, MRR |

---

## 6. Risks

1. **Competitor distribution** — Deno and GitHub. Without a clear differentiator
   (protocol awareness, self-host), Honmoon gets buried.
2. **Monetization timing** — pouring resources into paid features before a team buyer
   exists kills adoption.
3. **Wrong open-core boundary** — too thin a core fails adoption; too complete a core
   removes the reason to pay. **Tuning this boundary is the product's core decision.**

---

## 7. Next actions

- [ ] Finalize licensing → `LICENSE` (Apache-2.0) + `LICENSE.enterprise` (BSL/FSL), update `Cargo.toml`/`package.json`
- [ ] Split directories to reflect the paid boundary (`packages/enterprise/`, `apps/cloud/`)
- [ ] Define the OSS core MVP (document exactly what stays free)
- [ ] Scope a hosted management-plane PoC
