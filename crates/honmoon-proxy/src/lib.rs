//! Honmoon wire-level proxy and protocol parsers.
//!
//! Accepts agent connections, extracts protocol [`Facts`](honmoon_core::Facts),
//! and applies the [`Policy`](honmoon_core::Policy) via the policy engine in
//! `honmoon-core` before forwarding upstream.

pub mod approval;
pub mod gateway;
