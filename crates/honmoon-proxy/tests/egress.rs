//! Hermetic integration test for the Phase 1 CONNECT egress proxy.
//!
//! No external processes (no curl/python): an in-process TCP upstream and a
//! hand-rolled CONNECT client exercise the real `gateway::run` proxy over
//! loopback. Proves the Phase 1 exit criteria: an allowed host tunnels through
//! while a denied host is blocked with 403.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use honmoon_core::Policy;

/// A minimal HTTP upstream that answers every connection with `200 OK / "ok"`.
fn start_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let _ =
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    port
}

/// Start the egress proxy on a freshly bound loopback listener and return its port.
///
/// Binds here and hands the socket to the proxy thread (same pattern as
/// `honmoon run`), so there is no free-port-then-rebind race.
fn start_proxy(policy: Policy) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || honmoon_proxy::gateway::serve_listener(policy, listener));
    for _ in 0..250 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return port;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("proxy did not start listening on {port}");
}

fn connect_to_proxy(port: u16) -> TcpStream {
    let s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

/// Read bytes until the end of the HTTP response head (`\r\n\r\n`).
fn read_head(s: &mut TcpStream) -> String {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    while s.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
        out.push(byte[0]);
        if out.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn allow_policy(host: &str) -> Policy {
    Policy::from_yaml(&format!(
        "egress:\n  default: deny\n  allow:\n    - {host}\n"
    ))
    .unwrap()
}

#[test]
fn denied_host_is_blocked_with_403() {
    let proxy = start_proxy(allow_policy("allowed.example"));

    let mut s = connect_to_proxy(proxy);
    s.write_all(b"CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example:443\r\n\r\n")
        .unwrap();
    let resp = read_head(&mut s);

    assert!(
        resp.starts_with("HTTP/1.1 403"),
        "expected 403, got: {resp:?}"
    );
}

#[test]
fn allowed_host_tunnels_through_to_upstream() {
    let upstream = start_upstream();
    let proxy = start_proxy(allow_policy("127.0.0.1"));

    let mut s = connect_to_proxy(proxy);
    let target = format!("127.0.0.1:{upstream}");
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .unwrap();

    let established = read_head(&mut s);
    assert!(
        established.starts_with("HTTP/1.1 200"),
        "tunnel not established: {established:?}"
    );

    // Speak plain HTTP through the established tunnel to the upstream.
    s.write_all(b"GET / HTTP/1.0\r\nHost: upstream\r\n\r\n")
        .unwrap();
    let mut body = String::new();
    s.read_to_string(&mut body).unwrap();
    assert!(body.contains("200 OK"), "upstream response: {body:?}");
    assert!(body.trim_end().ends_with("ok"), "upstream body: {body:?}");
}

#[test]
fn non_connect_method_is_rejected() {
    let proxy = start_proxy(allow_policy("127.0.0.1"));

    let mut s = connect_to_proxy(proxy);
    s.write_all(b"GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .unwrap();
    let resp = read_head(&mut s);

    assert!(
        resp.starts_with("HTTP/1.1 405"),
        "expected 405, got: {resp:?}"
    );
}
