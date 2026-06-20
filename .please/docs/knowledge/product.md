# Product

> Stable product context for Honmoon. Source of truth for vision and scope.

## Vision

Honmoon is a **policy-based firewall gateway** that guards the boundary between AI agents
and production systems. It intercepts an agent's network traffic and applies policy
**before** requests reach their destination — allowing, denying, or holding each one for
human approval.

## Problem

AI agents run shell commands, call APIs, and access databases. A single bad inference can
trigger unintended data exfiltration, destructive queries (`DROP TABLE`), unauthorized
Kubernetes resource deletion, or tokens sent to a private endpoint. Existing controls are
either too coarse (block all network) or too narrow (HTTP domain allowlist only).

## What Honmoon does

It unifies two layers of protection in one product:

1. **Egress domain filtering** — restrict outbound HTTP/HTTPS with a domain allowlist/denylist
   (the [gh-aw-firewall](https://github.com/github/gh-aw-firewall) approach).
2. **Protocol-aware policy engine** — parse SQL, Kubernetes, and HTTP at the wire level and
   apply fine-grained rules via CEL conditions (the [clawpatrol](https://github.com/denoland/clawpatrol) approach).

Three verdicts: `allow`, `deny`, `pause` (human approval).

## Target users

- **Primary buyer**: platform / security teams running fleets of AI agents.
- **Adopter**: individual developers and small teams self-hosting the OSS core on a single node.

The buyer that pays is the team that needs centralized management, compliance, and approval —
not the individual developer. Adoption is driven by a generous, auditable OSS core.

## Operating modes

- **Process Wrapper** (`honmoon run -- <cmd>`) — isolate a single process (netns / NetworkExtension).
- **Gateway** (`honmoon gateway`) — central proxy loading policy, accepting client connections.
- **Join** (`honmoon join`) — route all host traffic to the gateway through a tunnel.

## Business model

Open core. The data plane is 100% open source (trust = adoption); the control/cloud plane
(fleet management, compliance, approval routing, hosted SaaS) is monetized.
See [`docs/business-model.md`](../../../docs/business-model.md) for the full model.

## Out of scope (for now)

- Transparent L3/L4 interception on serverless isolate platforms (e.g. Cloudflare Workers) —
  the wire-level core requires a host or container. Workers can host the egress-filter +
  control plane only.
- Decryption-based deep packet inspection beyond declared protocol facts.

## Differentiation (moat)

Protocol awareness (SQL/K8s parsing) + multi-runtime + self-hostable. A plain domain
allowlist cannot win against Deno/GitHub distribution; the wire-level protocol engine is the moat.
