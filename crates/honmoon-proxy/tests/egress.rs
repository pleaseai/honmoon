//! Hermetic integration test for the Phase 1 CONNECT egress proxy.
//!
//! No external processes (no curl/python): an in-process TCP upstream and a
//! hand-rolled CONNECT client exercise the real `gateway::run` proxy over
//! loopback. Proves the Phase 1 exit criteria: an allowed host tunnels through
//! while a denied host is blocked with 403.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use honmoon_core::Policy;
use honmoon_proxy::gateway::HEAD_READ_TIMEOUT;

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

/// An upstream that answers `200 OK` with the request head it received as the
/// body, so a test can assert on the bytes that reached the far side verbatim.
fn start_head_echo_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while s.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let _ = s.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    head.len()
                )
                .as_bytes(),
            );
            let _ = s.write_all(&head);
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

/// Cleartext `http://` forward-proxy requests are also subject to the egress
/// allowlist — a request to a denied host must be blocked, not silently
/// forwarded (no bypass by skipping CONNECT). Since adopting hudsucker the proxy
/// handles plain HTTP too, so the Phase 1 `405` is replaced by this stronger
/// property.
#[test]
fn plain_http_to_denied_host_is_blocked_with_403() {
    let proxy = start_proxy(allow_policy("allowed.example"));

    let mut s = connect_to_proxy(proxy);
    s.write_all(b"GET http://blocked.example/ HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
        .unwrap();
    let resp = read_head(&mut s);

    assert!(
        resp.starts_with("HTTP/1.1 403"),
        "expected 403, got: {resp:?}"
    );
}

/// An absolute-form `https://` request sent *without* a prior CONNECT must not
/// skip the host gate: the scheme alone doesn't prove the tunnel was authorized
/// (hudsucker forwards such requests like any other), so trusting it would let
/// a client bypass the egress allowlist.
#[test]
fn absolute_form_https_without_connect_is_blocked_with_403() {
    let proxy = start_proxy(allow_policy("allowed.example"));

    let mut s = connect_to_proxy(proxy);
    s.write_all(b"GET https://blocked.example/ HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
        .unwrap();
    let resp = read_head(&mut s);

    assert!(
        resp.starts_with("HTTP/1.1 403"),
        "expected 403, got: {resp:?}"
    );
}

/// Origin-form requests (`GET /`) carry their destination only in the `Host`
/// header; the gate must fall back to it rather than evaluating an empty host.
#[test]
fn origin_form_request_is_gated_via_host_header() {
    let proxy = start_proxy(allow_policy("allowed.example"));

    let mut s = connect_to_proxy(proxy);
    s.write_all(b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
        .unwrap();
    let resp = read_head(&mut s);

    assert!(
        resp.starts_with("HTTP/1.1 403"),
        "expected 403, got: {resp:?}"
    );
}

/// A client that opens a connection and never finishes its request head must be
/// dropped rather than held forever (#267).
///
/// hudsucker supplies hyper no `Timer`, and hyper's `header_read_timeout`
/// default silently does not arm without one — so before the gateway passed its
/// own server builder this connection stayed open for the life of the process,
/// one task and one file descriptor each. The gateway now bounds the head read
/// at [`HEAD_READ_TIMEOUT`], after which hyper drops the connection (it writes
/// no response: the head it would have answered never arrived).
#[test]
fn partial_request_head_is_dropped_after_the_head_read_timeout() {
    let proxy = start_proxy(allow_policy("allowed.example"));

    let mut s = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    // Comfortably past the proxy's own bound, so a failure here reads as "the
    // proxy did not close the connection" rather than as a hung suite.
    let bound = HEAD_READ_TIMEOUT * 3;
    s.set_read_timeout(Some(bound)).unwrap();

    // A head that never terminates: header lines, but no blank line after them.
    s.write_all(b"CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\n")
        .unwrap();

    let started = Instant::now();
    let mut buf = [0u8; 256];
    loop {
        match s.read(&mut buf) {
            // FIN — the proxy closed it.
            Ok(0) => break,
            // A refusal head first would also be fine; keep reading to the close.
            Ok(_) => continue,
            Err(e) if e.kind() == ErrorKind::ConnectionReset => break,
            Err(e) => panic!(
                "proxy held a partially-sent request head for {bound:?} without closing it: {e}"
            ),
        }
    }
    assert!(
        started.elapsed() < bound,
        "connection closed only after {:?}, past the {bound:?} bound",
        started.elapsed()
    );
}

/// Supplying a server builder to hudsucker *replaces* the one it would have
/// built, so the two settings it puts there — `title_case_headers` and
/// `preserve_header_case` — are lost unless honmoon repeats them. Losing them is
/// a wire-fidelity regression on a proxy: hyper would normalize every received
/// header name to lowercase and the upstream would see a request honmoon's
/// client never sent. Assert the original casing survives the round trip.
#[test]
fn forwarded_request_preserves_the_client_header_casing() {
    let upstream = start_head_echo_upstream();
    let proxy = start_proxy(allow_policy("127.0.0.1"));

    let mut s = connect_to_proxy(proxy);
    s.write_all(
        format!(
            "GET http://127.0.0.1:{upstream}/ HTTP/1.1\r\n\
             Host: 127.0.0.1:{upstream}\r\n\
             x-CUSTOM-Header: kept\r\n\r\n"
        )
        .as_bytes(),
    )
    .unwrap();

    let mut response = String::new();
    s.read_to_string(&mut response).unwrap();
    assert!(
        response.contains("x-CUSTOM-Header"),
        "upstream saw a renormalized header name: {response:?}"
    );
    // The response side pins the other setting: `Date` is hyper's own header,
    // so its casing comes from `title_case_headers` rather than from anything
    // the upstream wrote.
    assert!(
        response.contains("\r\nDate:"),
        "response header names were not title-cased: {response:?}"
    );
}

/// An upstream that answers every request on a connection and never closes it,
/// so the client-side connection stays keep-alive and the test controls when it
/// goes idle.
fn start_keep_alive_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while matches!(s.read(&mut buf), Ok(n) if n > 0) {
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                }
            });
        }
    });
    port
}

/// [`HEAD_READ_TIMEOUT`] governs the idle gap on a keep-alive connection as well
/// as a partial head, because hyper re-arms the timer on every head read and an
/// idle keep-alive connection is parked in exactly that read.
///
/// That coupling is the reason the bound is hyper's 30s default rather than the
/// 10s its one-shot namesakes (`socks::HANDSHAKE_TIMEOUT`, the Phase 1 constant)
/// use, so it is pinned here: a future edit that re-tightens the constant on the
/// stalled-head argument alone would be shortening a client's idle-pool budget
/// without meaning to, and this test is what says so.
#[test]
fn an_idle_keep_alive_connection_is_held_for_the_head_read_timeout() {
    let upstream = start_keep_alive_upstream();
    let proxy = start_proxy(allow_policy("127.0.0.1"));

    let mut s = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    s.set_read_timeout(Some(HEAD_READ_TIMEOUT * 3)).unwrap();
    s.write_all(
        format!("GET http://127.0.0.1:{upstream}/ HTTP/1.1\r\nHost: 127.0.0.1:{upstream}\r\n\r\n")
            .as_bytes(),
    )
    .unwrap();

    let mut buf = [0u8; 1024];
    let n = s.read(&mut buf).expect("first response");
    let response = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected the request to be proxied: {response:?}"
    );

    // Now go idle on the same connection. hyper is waiting for the next head.
    let idle_started = Instant::now();
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(e) if e.kind() == ErrorKind::ConnectionReset => break,
            Err(e) => panic!("idle keep-alive connection was never closed: {e}"),
        }
    }
    let idle = idle_started.elapsed();

    // The floor is the point of the test: an idle client must keep its pooled
    // connection for the whole budget, not merely lose it eventually. The
    // allowance absorbs the first request's own share of the re-armed timer.
    assert!(
        idle > HEAD_READ_TIMEOUT - Duration::from_secs(5),
        "idle keep-alive connection was dropped after only {idle:?}, \
         well inside the {HEAD_READ_TIMEOUT:?} budget"
    );
    assert!(
        idle < HEAD_READ_TIMEOUT * 2,
        "idle keep-alive connection outlived {:?}, so the bound did not govern it",
        HEAD_READ_TIMEOUT * 2
    );
}
