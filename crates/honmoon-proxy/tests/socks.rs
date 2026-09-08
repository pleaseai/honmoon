//! Hermetic SOCKS5 + inline PostgreSQL runtime integration test.
//!
//! No external processes and no database: a fake PostgreSQL upstream and a
//! plain echo upstream on loopback, driven through the real `serve_socks`
//! listener by a hand-rolled SOCKS5 client and a hand-rolled PostgreSQL client.
//! Proves the #86 exit criteria — a `DROP` never reaches the database while the
//! session survives, a `SELECT` does, a paused statement waits for a human, and
//! a non-endpoint host is tunnelled or refused by the egress lists.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use honmoon_core::Policy;
use honmoon_proxy::approval::{ApprovalDecision, ApprovalRegistry};
use honmoon_proxy::gateway::GatewayState;

/// PostgreSQL protocol constants the client helpers below speak.
const PROTOCOL_V3: u32 = 196_608;
const SSL_REQUEST: u32 = 80_877_103;
const CANCEL_REQUEST: u32 = 80_877_102;

// --- fake upstreams ---------------------------------------------------------

/// A fake PostgreSQL server: completes startup, then answers `Q` with
/// `CommandComplete` + `ReadyForQuery` and `P` with `ParseComplete`. Every SQL
/// statement it actually receives is reported on the returned channel, so a test
/// can assert that a refused statement never arrived.
///
/// It tracks the transaction status the way a real server does (`BEGIN` opens
/// one), and answers `SELECT huge` with a backend message far larger than the
/// relay's buffering cap.
fn start_pg_upstream() -> (u16, Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let tx = tx.clone();
            thread::spawn(move || {
                // StartupMessage: Int32 length (self-inclusive) + body.
                let mut len_bytes = [0u8; 4];
                if s.read_exact(&mut len_bytes).is_err() {
                    return;
                }
                let len = u32::from_be_bytes(len_bytes) as usize;
                let mut startup = vec![0u8; len - 4];
                if s.read_exact(&mut startup).is_err() {
                    return;
                }
                // AuthenticationOk, then ReadyForQuery(idle).
                let mut hello = vec![b'R', 0, 0, 0, 8, 0, 0, 0, 0];
                hello.extend_from_slice(&[b'Z', 0, 0, 0, 5, b'I']);
                if s.write_all(&hello).is_err() {
                    return;
                }

                let mut status = b'I';
                loop {
                    let mut tag = [0u8; 1];
                    if s.read_exact(&mut tag).is_err() {
                        return;
                    }
                    let mut len_bytes = [0u8; 4];
                    if s.read_exact(&mut len_bytes).is_err() {
                        return;
                    }
                    let len = u32::from_be_bytes(len_bytes) as usize;
                    let mut payload = vec![0u8; len - 4];
                    if s.read_exact(&mut payload).is_err() {
                        return;
                    }

                    let reply = match tag[0] {
                        b'Q' => {
                            let sql = payload.strip_suffix(&[0]).unwrap_or(&payload);
                            let sql = String::from_utf8_lossy(sql).into_owned();
                            let statement = sql.trim().trim_end_matches(';').to_ascii_uppercase();
                            match statement.as_str() {
                                "BEGIN" => status = b'T',
                                "COMMIT" | "ROLLBACK" => status = b'I',
                                _ => {}
                            }
                            tx.send(sql).unwrap();

                            let mut out = Vec::new();
                            if statement == "SELECT HUGE" {
                                let row = vec![b'x'; 256 * 1024];
                                out.push(b'D');
                                out.extend_from_slice(&((4 + row.len()) as u32).to_be_bytes());
                                out.extend_from_slice(&row);
                            }
                            let complete = b"SELECT 1\0";
                            out.push(b'C');
                            out.extend_from_slice(&((4 + complete.len()) as u32).to_be_bytes());
                            out.extend_from_slice(complete);
                            out.extend_from_slice(&[b'Z', 0, 0, 0, 5, status]);
                            out
                        }
                        b'P' => {
                            let mut parts = payload.splitn(3, |b| *b == 0);
                            parts.next();
                            let query = parts.next().unwrap_or_default();
                            tx.send(String::from_utf8_lossy(query).into_owned())
                                .unwrap();
                            vec![b'1', 0, 0, 0, 4]
                        }
                        _ => continue,
                    };
                    if s.write_all(&reply).is_err() {
                        return;
                    }
                }
            });
        }
    });
    (port, rx)
}

/// A plain TCP echo server, for the raw-tunnel case.
fn start_echo_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

// --- proxy under test -------------------------------------------------------

fn start_socks_proxy(policy_yaml: &str) -> (u16, Arc<ApprovalRegistry>) {
    let policy = Policy::from_yaml(policy_yaml).unwrap();
    let state = GatewayState::new(policy);
    let approvals = Arc::clone(&state.approvals);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(honmoon_proxy::socks::serve_socks(state, listener));
    });
    for _ in 0..250 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return (port, approvals);
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("SOCKS5 listener did not start on {port}");
}

/// The policy every PostgreSQL test runs against: `postgres-prod` points at the
/// fake upstream, destructive verbs are denied, `DELETE` is held for approval,
/// and `blocked.test` is refused by the egress deny list.
fn policy_yaml(upstream: u16) -> String {
    format!(
        r#"
endpoints:
  postgres-prod: {{ host: localhost, port: {upstream}, protocol: postgres }}
egress:
  default: allow
  deny:
    - blocked.test
rules:
  - name: no-destructive-sql
    endpoint: postgres-prod
    condition: "sql.verb == 'DROP' || sql.verb == 'TRUNCATE'"
    verdict: deny
  - name: review-delete
    endpoint: postgres-prod
    condition: "sql.verb == 'DELETE'"
    verdict: pause
"#
    )
}

/// A default-deny policy for the same endpoint. `allow_endpoint` appends an
/// explicit connection-level `allow` rule **after** the DROP deny, so the
/// statement rule still wins on a `DROP` (first match wins).
fn deny_default_policy_yaml(upstream: u16, allow_endpoint: bool) -> String {
    let allow_rule = if allow_endpoint {
        r#"
  - name: allow-postgres-prod
    endpoint: postgres-prod
    condition: "true"
    verdict: allow
"#
    } else {
        ""
    };
    format!(
        r#"
endpoints:
  postgres-prod:
    host: localhost
    port: {upstream}
    protocol: postgres
egress:
  default: deny
rules:
  - name: no-destructive-sql
    endpoint: postgres-prod
    condition: "sql.verb == 'DROP' || sql.verb == 'TRUNCATE'"
    verdict: deny{allow_rule}
"#
    )
}

// --- SOCKS5 client ----------------------------------------------------------

/// Greet, then send a `CONNECT` for `host:port` with the DOMAIN address type.
/// Returns the connection and the reply code.
fn socks_connect(proxy: u16, host: &str, port: u16) -> (TcpStream, u8) {
    socks_request(proxy, 0x01, host, port)
}

fn socks_request(proxy: u16, command: u8, host: &str, port: u16) -> (TcpStream, u8) {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();

    s.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut greeting = [0u8; 2];
    s.read_exact(&mut greeting).unwrap();
    assert_eq!(greeting, [0x05, 0x00], "no-auth must be selected");

    let mut request = vec![0x05, command, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    s.write_all(&request).unwrap();

    let mut head = [0u8; 4];
    s.read_exact(&mut head).unwrap();
    let address_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).unwrap();
            usize::from(len[0])
        }
        other => panic!("unexpected bound address type {other}"),
    };
    let mut rest = vec![0u8; address_len + 2];
    s.read_exact(&mut rest).unwrap();
    (s, head[1])
}

// --- PostgreSQL client ------------------------------------------------------

fn ssl_request(s: &mut TcpStream) -> u8 {
    let mut message = Vec::new();
    message.extend_from_slice(&8u32.to_be_bytes());
    message.extend_from_slice(&SSL_REQUEST.to_be_bytes());
    s.write_all(&message).unwrap();
    let mut answer = [0u8; 1];
    s.read_exact(&mut answer).unwrap();
    answer[0]
}

/// Send a 3.0 `StartupMessage` and read until `ReadyForQuery`.
fn startup(s: &mut TcpStream) {
    let body = b"user\0honmoon\0\0";
    let mut message = Vec::new();
    message.extend_from_slice(&((8 + body.len()) as u32).to_be_bytes());
    message.extend_from_slice(&PROTOCOL_V3.to_be_bytes());
    message.extend_from_slice(body);
    s.write_all(&message).unwrap();
    read_until_ready(s);
}

/// A full client handshake: refuse TLS, then start up.
fn pg_connect(proxy: u16, port: u16) -> TcpStream {
    let (mut s, code) = socks_connect(proxy, "localhost", port);
    assert_eq!(code, 0x00, "SOCKS5 CONNECT to the endpoint must succeed");
    assert_eq!(ssl_request(&mut s), b'N');
    startup(&mut s);
    s
}

fn simple_query(sql: &str) -> Vec<u8> {
    let mut frame = vec![b'Q'];
    frame.extend_from_slice(&((5 + sql.len()) as u32).to_be_bytes());
    frame.extend_from_slice(sql.as_bytes());
    frame.push(0);
    frame
}

fn parse_frame(name: &str, sql: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(name.as_bytes());
    payload.push(0);
    payload.extend_from_slice(sql.as_bytes());
    payload.push(0);
    payload.extend_from_slice(&0i16.to_be_bytes());

    let mut frame = vec![b'P'];
    frame.extend_from_slice(&((4 + payload.len()) as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

fn read_frame(s: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut tag = [0u8; 1];
    s.read_exact(&mut tag).unwrap();
    let mut len_bytes = [0u8; 4];
    s.read_exact(&mut len_bytes).unwrap();
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut payload = vec![0u8; len - 4];
    s.read_exact(&mut payload).unwrap();
    (tag[0], payload)
}

/// Read frames until `ReadyForQuery`, returning everything seen (that frame
/// included).
fn read_until_ready(s: &mut TcpStream) -> Vec<(u8, Vec<u8>)> {
    let mut frames = Vec::new();
    loop {
        let frame = read_frame(s);
        let done = frame.0 == b'Z';
        frames.push(frame);
        if done {
            return frames;
        }
    }
}

/// Assert the frames carry honmoon's refusal: `ErrorResponse` (SQLSTATE 42501)
/// followed by `ReadyForQuery` reporting the session as idle.
fn assert_refused(frames: &[(u8, Vec<u8>)]) {
    assert_refused_with_status(frames, b'I');
}

/// As [`assert_refused`], but for a refusal whose `ReadyForQuery` must report
/// `status` — the transaction state the upstream is actually in.
fn assert_refused_with_status(frames: &[(u8, Vec<u8>)], status: u8) {
    assert_eq!(frames.len(), 2, "expected ErrorResponse + ReadyForQuery");
    assert_eq!(frames[0].0, b'E', "first frame must be an ErrorResponse");
    let body = String::from_utf8_lossy(&frames[0].1);
    assert!(
        body.contains("C42501\0"),
        "SQLSTATE 42501 expected: {body:?}"
    );
    assert!(body.contains("honmoon:"), "message names honmoon: {body:?}");
    assert_eq!(frames[1].0, b'Z');
    assert_eq!(
        frames[1].1,
        vec![status],
        "the refusal reports the upstream's transaction status"
    );
}

/// Nothing should have reached the database.
fn assert_upstream_silent(upstream: &Receiver<String>) {
    assert_eq!(
        upstream.recv_timeout(Duration::from_millis(300)).ok(),
        None,
        "a refused statement must never reach the database"
    );
}

// --- tests ------------------------------------------------------------------

#[test]
fn ssl_request_is_refused_with_n_and_startup_proceeds() {
    let (upstream, _sql) = start_pg_upstream();
    let (proxy, _) = start_socks_proxy(&policy_yaml(upstream));

    let (mut s, code) = socks_connect(proxy, "localhost", upstream);
    assert_eq!(code, 0x00);
    assert_eq!(
        ssl_request(&mut s),
        b'N',
        "inline inspection needs plaintext, so TLS is declined"
    );
    // The client falls back to plaintext and the session comes up.
    startup(&mut s);
}

#[test]
fn select_is_forwarded_and_upstream_reply_returned() {
    let (upstream, sql) = start_pg_upstream();
    let (proxy, _) = start_socks_proxy(&policy_yaml(upstream));

    let mut s = pg_connect(proxy, upstream);
    s.write_all(&simple_query("SELECT * FROM orders")).unwrap();

    assert_eq!(
        sql.recv_timeout(Duration::from_secs(5)).unwrap(),
        "SELECT * FROM orders"
    );
    let frames = read_until_ready(&mut s);
    assert_eq!(frames[0].0, b'C', "upstream CommandComplete is relayed");
}

#[test]
fn drop_table_is_refused_with_error_response_and_never_reaches_upstream() {
    let (upstream, sql) = start_pg_upstream();
    let (proxy, _) = start_socks_proxy(&policy_yaml(upstream));

    let mut s = pg_connect(proxy, upstream);
    s.write_all(&simple_query("DROP TABLE users")).unwrap();

    assert_refused(&read_until_ready(&mut s));
    assert_upstream_silent(&sql);

    // The session survives the refusal: the next statement still works.
    s.write_all(&simple_query("SELECT 1")).unwrap();
    assert_eq!(
        sql.recv_timeout(Duration::from_secs(5)).unwrap(),
        "SELECT 1"
    );
    assert_eq!(read_until_ready(&mut s)[0].0, b'C');
}

#[test]
fn multi_statement_simple_query_is_refused_and_single_statements_are_not() {
    let (upstream, sql) = start_pg_upstream();
    let (proxy, _) = start_socks_proxy(&policy_yaml(upstream));

    let mut s = pg_connect(proxy, upstream);
    // The policy only ever sees the leading `SELECT`, so forwarding this frame
    // would run a `DROP` no rule ever decided.
    s.write_all(&simple_query("SELECT 1; DROP TABLE users"))
        .unwrap();
    assert_refused(&read_until_ready(&mut s));
    assert_upstream_silent(&sql);

    // The ordinary single-statement shapes still go through.
    for statement in ["SELECT 1;", "SELECT ';' FROM orders"] {
        s.write_all(&simple_query(statement)).unwrap();
        assert_eq!(sql.recv_timeout(Duration::from_secs(5)).unwrap(), statement);
        assert_eq!(read_until_ready(&mut s)[0].0, b'C');
    }
}

#[test]
fn a_do_block_is_refused_and_never_reaches_upstream() {
    let (upstream, sql) = start_pg_upstream();
    let (proxy, _) = start_socks_proxy(&policy_yaml(upstream));

    let mut s = pg_connect(proxy, upstream);
    // The body is PL/pgSQL, so no rule can see the DELETE inside it — the
    // statement would reach the database reporting only the verb `DO`.
    s.write_all(&simple_query("DO $$ BEGIN DELETE FROM users; END $$"))
        .unwrap();
    assert_refused(&read_until_ready(&mut s));
    assert_upstream_silent(&sql);

    // The refusal is specific to the block, not a dead session.
    s.write_all(&simple_query("SELECT 1")).unwrap();
    assert_eq!(
        sql.recv_timeout(Duration::from_secs(5)).unwrap(),
        "SELECT 1"
    );
    assert_eq!(read_until_ready(&mut s)[0].0, b'C');
}

#[test]
fn a_refusal_inside_a_transaction_reports_the_upstream_status() {
    let (upstream, sql) = start_pg_upstream();
    let (proxy, _) = start_socks_proxy(&policy_yaml(upstream));

    let mut s = pg_connect(proxy, upstream);
    s.write_all(&simple_query("BEGIN")).unwrap();
    assert_eq!(sql.recv_timeout(Duration::from_secs(5)).unwrap(), "BEGIN");
    assert_eq!(
        read_until_ready(&mut s).last().unwrap().1,
        vec![b'T'],
        "the upstream opened a transaction"
    );

    // The upstream transaction is still open, so telling the client it is idle
    // would have it make transaction-bound decisions on a wrong state.
    s.write_all(&simple_query("DROP TABLE users")).unwrap();
    assert_refused_with_status(&read_until_ready(&mut s), b'T');
    assert_upstream_silent(&sql);
}

#[test]
fn a_backend_message_larger_than_the_relay_buffer_arrives_intact() {
    let (upstream, sql) = start_pg_upstream();
    let (proxy, _) = start_socks_proxy(&policy_yaml(upstream));

    let mut s = pg_connect(proxy, upstream);
    s.write_all(&simple_query("SELECT huge")).unwrap();
    assert_eq!(
        sql.recv_timeout(Duration::from_secs(5)).unwrap(),
        "SELECT huge"
    );

    // Past the relay's buffering cap, so the message takes the streaming path.
    let (tag, payload) = read_frame(&mut s);
    assert_eq!(tag, b'D');
    assert_eq!(payload.len(), 256 * 1024);
    assert!(payload.iter().all(|b| *b == b'x'), "relayed unmangled");
    assert_eq!(read_until_ready(&mut s)[0].0, b'C');
}

#[test]
fn cancel_request_ends_the_session_without_waiting_for_client_eof() {
    let (upstream, _sql) = start_pg_upstream();
    let (proxy, _) = start_socks_proxy(&policy_yaml(upstream));

    let (mut s, code) = socks_connect(proxy, "localhost", upstream);
    assert_eq!(code, 0x00);

    // 16 bytes: length, the cancel code, then the backend PID and secret key.
    let mut packet = Vec::new();
    packet.extend_from_slice(&16u32.to_be_bytes());
    packet.extend_from_slice(&CANCEL_REQUEST.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 7, 0, 0, 0, 42]);
    s.write_all(&packet).unwrap();

    // A `CancelRequest` is a complete packet, so the runtime lets go of the
    // connection instead of pinning it until this client — which never closes —
    // sends EOF.
    let mut rest = Vec::new();
    s.read_to_end(&mut rest)
        .expect("the session must end without waiting for the client to close");
}

#[test]
fn parse_frame_carrying_truncate_is_refused() {
    let (upstream, sql) = start_pg_upstream();
    let (proxy, _) = start_socks_proxy(&policy_yaml(upstream));

    let mut s = pg_connect(proxy, upstream);
    s.write_all(&parse_frame("stmt1", "TRUNCATE accounts"))
        .unwrap();

    assert_refused(&read_until_ready(&mut s));
    assert_upstream_silent(&sql);
}

#[test]
fn pause_rule_holds_until_approved_then_forwards() {
    let (upstream, sql) = start_pg_upstream();
    let (proxy, approvals) = start_socks_proxy(&policy_yaml(upstream));

    let mut s = pg_connect(proxy, upstream);
    s.write_all(&simple_query("DELETE FROM sessions")).unwrap();

    // Approve from outside, the way the dashboard does.
    let approver = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Some(pending) = approvals.pending().first() {
                assert_eq!(pending.rule.as_deref(), Some("review-delete"));
                approvals.resolve(pending.id, ApprovalDecision::Approve);
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("statement was never held for approval");
    });
    approver.join().unwrap();

    assert_eq!(
        sql.recv_timeout(Duration::from_secs(5)).unwrap(),
        "DELETE FROM sessions",
        "an approved statement is forwarded"
    );
    assert_eq!(read_until_ready(&mut s)[0].0, b'C');
}

#[test]
fn over_cap_query_frame_is_refused() {
    let (upstream, sql) = start_pg_upstream();
    let (proxy, _) = start_socks_proxy(&policy_yaml(upstream));

    let mut s = pg_connect(proxy, upstream);

    // A `SELECT` padded past the 1 MiB inspection cap: honmoon cannot inspect
    // it, so it fails closed rather than forwarding it un-inspected.
    let declared = honmoon_proxy::runtime::postgres::MAX_PG_FRAME + 1;
    let mut frame = vec![b'Q'];
    frame.extend_from_slice(&(declared as u32).to_be_bytes());
    frame.resize(5 + declared - 4, b' ');
    s.write_all(&frame).unwrap();

    assert_refused(&read_until_ready(&mut s));
    assert_upstream_silent(&sql);
}

#[test]
fn non_endpoint_host_is_tunnelled_raw_when_allowed() {
    let (pg, _sql) = start_pg_upstream();
    let echo = start_echo_upstream();
    let (proxy, _) = start_socks_proxy(&policy_yaml(pg));

    let (mut s, code) = socks_connect(proxy, "localhost", echo);
    assert_eq!(code, 0x00, "an allowed host is tunnelled");

    s.write_all(b"ping").unwrap();
    let mut echoed = [0u8; 4];
    s.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"ping", "bytes cross the tunnel untouched");
}

#[test]
fn denied_domain_gets_socks_reply_0x02() {
    let (pg, _sql) = start_pg_upstream();
    let (proxy, _) = start_socks_proxy(&policy_yaml(pg));

    let (_s, code) = socks_connect(proxy, "blocked.test", 9);
    assert_eq!(
        code, 0x02,
        "denied by the egress list → not allowed by ruleset"
    );
}

#[test]
fn bind_command_is_rejected_with_0x07() {
    let (pg, _sql) = start_pg_upstream();
    let (proxy, _) = start_socks_proxy(&policy_yaml(pg));

    let (_s, code) = socks_request(proxy, 0x02, "localhost", pg);
    assert_eq!(code, 0x07, "BIND is not a supported command");
}

#[test]
fn postgres_endpoint_is_gated_at_connection_time_by_the_egress_default() {
    let (upstream, sql) = start_pg_upstream();

    // Without a connection-level allow, the egress default refuses the
    // connection outright — a declared endpoint is not a way past default-deny.
    let (refusing, _) = start_socks_proxy(&deny_default_policy_yaml(upstream, false));
    let (_s, code) = socks_connect(refusing, "localhost", upstream);
    assert_eq!(
        code, 0x02,
        "default-deny must refuse the postgres endpoint too"
    );

    // With an explicit allow rule ordered after the DROP deny, the connection
    // comes up and statement rules still decide each query.
    let (proxy, _) = start_socks_proxy(&deny_default_policy_yaml(upstream, true));
    let mut s = pg_connect(proxy, upstream);

    s.write_all(&simple_query("SELECT 1")).unwrap();
    assert_eq!(
        sql.recv_timeout(Duration::from_secs(5)).unwrap(),
        "SELECT 1"
    );
    assert_eq!(read_until_ready(&mut s)[0].0, b'C');

    s.write_all(&simple_query("DROP TABLE users")).unwrap();
    assert_refused(&read_until_ready(&mut s));
    assert_upstream_silent(&sql);
}
