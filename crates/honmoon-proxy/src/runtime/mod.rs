//! Protocol runtimes: inline policy enforcement on a non-HTTP stream.
//!
//! A runtime receives a connection whose intended endpoint is already known
//! (the SOCKS5 handshake in [`crate::socks`] declared it), parses the wire
//! protocol into [`Facts`](honmoon_core::Facts), calls the policy engine per
//! message, and forwards, refuses, or holds for approval — see [ADR-0005] §4.
//! Transport and runtime stay separate so a future L3 dispatch (`honmoon join`)
//! can reuse the same runtimes untouched.
//!
//! [ADR-0005]: ../../../../.please/docs/decisions/0005-empty-namespace-and-bridged-proxy-sockets.md

pub mod postgres;
