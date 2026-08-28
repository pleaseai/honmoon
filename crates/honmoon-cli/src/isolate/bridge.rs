//! Byte pumps that carry a connection across the namespace boundary.
//!
//! Enforced isolation leaves the child's network namespace empty, so the child
//! cannot reach the proxy's host loopback address. A Unix socket can cross that
//! boundary — it is addressed by filesystem path, not by network namespace — so
//! two pumps sit on either side of it:
//!
//! - on the host, [`serve`] accepts on the Unix socket and dials the proxy;
//! - inside the namespace, [`serve`] accepts on loopback TCP and dials the Unix
//!   socket.
//!
//! Both directions are the same operation with the endpoint types swapped, which
//! is why [`Endpoint`] exists rather than two near-identical modules.

//! Kept portable rather than gated to Linux so the pump's own tests — the
//! half-close case and the survives-a-dead-upstream case, where the bugs live —
//! run on every developer's machine and not only in CI.
#![cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only the Linux isolation path bridges today")
)]

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

/// A stream this module can copy bytes through in both directions.
///
/// `TcpStream` and `UnixStream` already share the shape; the trait only names
/// the two operations a pump needs beyond `Read`/`Write`: a second handle for
/// the opposite direction, and a half-close so the peer sees EOF rather than
/// waiting on a connection nobody will write to again.
pub trait Endpoint: Read + Write + Send + Sized + 'static {
    fn duplicate(&self) -> io::Result<Self>;
    fn shutdown_write(&self) -> io::Result<()>;
}

impl Endpoint for TcpStream {
    fn duplicate(&self) -> io::Result<Self> {
        self.try_clone()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

impl Endpoint for UnixStream {
    fn duplicate(&self) -> io::Result<Self> {
        self.try_clone()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

/// Something that hands out inbound connections.
pub trait Listener: Send + 'static {
    type Stream: Endpoint;
    fn accept_one(&self) -> io::Result<Self::Stream>;
}

impl Listener for UnixListener {
    type Stream = UnixStream;

    fn accept_one(&self) -> io::Result<Self::Stream> {
        self.accept().map(|(stream, _)| stream)
    }
}

impl Listener for TcpListener {
    type Stream = TcpStream;

    fn accept_one(&self) -> io::Result<Self::Stream> {
        self.accept().map(|(stream, _)| stream)
    }
}

/// Where a pump sends the traffic it accepted.
pub trait Upstream: Send + Clone + 'static {
    type Stream: Endpoint;
    fn connect(&self) -> io::Result<Self::Stream>;
}

/// How many `accept` failures in a row before the pump concludes the listener is
/// gone rather than merely having a bad moment.
///
/// A cap rather than an unconditional retry: a listener that is genuinely broken
/// — a closed descriptor, say — fails instantly and forever, and an uncapped
/// loop would spin on it.
const ACCEPT_FAILURE_LIMIT: u32 = 64;

/// How long to wait before retrying a failed `accept`.
///
/// Short enough to be invisible to a client that is merely unlucky, long enough
/// that the retry budget above spans seconds rather than microseconds.
///
/// Lowered under `cfg(test)` so the sustained-pressure test below — which has to
/// out-fail the retry budget to prove anything — finishes in well under a second
/// instead of the three quarters of a minute the production pauses would cost.
#[cfg(not(test))]
const ACCEPT_RETRY_PAUSE: std::time::Duration = std::time::Duration::from_millis(20);
#[cfg(test)]
const ACCEPT_RETRY_PAUSE: std::time::Duration = std::time::Duration::from_millis(1);

/// The ceiling the retry pause escalates to while a recoverable failure lasts.
///
/// Descriptor exhaustion can persist for as long as whatever is holding the
/// descriptors holds them, and retrying every 20ms for that whole time is a
/// busy-wait. Backing off to half a second costs a client at most that much
/// latency on the connection that finally gets through, and costs nothing at all
/// in the overwhelmingly common case where the first retry succeeds.
#[cfg(not(test))]
const ACCEPT_RETRY_PAUSE_MAX: std::time::Duration = std::time::Duration::from_millis(500);
#[cfg(test)]
const ACCEPT_RETRY_PAUSE_MAX: std::time::Duration = std::time::Duration::from_millis(5);

/// How many connections may be bridged at once.
///
/// The cap exists because the child on the other end chooses how many
/// connections to open and how long to hold them, and every one of them costs
/// this process two threads. Without a ceiling a child that opens and retains
/// connections in a loop exhausts the host's thread or memory limits and takes
/// the supervisor down with it — which is to say it ends enforcement, the one
/// outcome this module exists to prevent.
///
/// The newest connection is the one dropped rather than the oldest: the client
/// reads a dropped connection as a closed one, which is exactly the signal a
/// denied dial already produces, so nothing downstream has to learn a new
/// failure mode.
const MAX_CONCURRENT_CONNECTIONS: usize = 256;

/// Is this `accept` failure one that clears on its own?
///
/// `ECONNABORTED` is a single peer that went away mid-handshake, `EINTR` is a
/// signal that happened to land on the call, and `EAGAIN` is a listener that had
/// nothing ready — none of the three say anything about the listener's health.
/// `EMFILE`/`ENFILE` mean this process or this host is momentarily out of
/// descriptors and `ENOBUFS`/`ENOMEM` that the kernel is out of socket buffers;
/// all four end when whatever is holding the resource releases it.
fn is_recoverable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
    ) || matches!(
        error.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    )
}

/// Holds one of the [`MAX_CONCURRENT_CONNECTIONS`] slots until its connection
/// ends, however it ends.
///
/// A guard rather than a `fetch_sub` at each exit point, because the spliced
/// path and the failed-dial path both leave the spawned closure and a count that
/// only decremented on one of them would drift upward until the cap refused
/// every connection — turning an admission-control measure into the outage it
/// was added to prevent.
struct ConnectionSlot(Arc<AtomicUsize>);

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Accept forever, and splice each connection onto a fresh upstream one.
///
/// A connection that cannot reach its upstream is dropped: the client sees a
/// closed connection, which is the correct signal that policy did not carry it,
/// and one failed dial must not take the accept loop down with it.
///
/// Neither may one failed *accept*. Failures that clear on their own —
/// `ECONNABORTED` from a peer that went away mid-handshake, `EMFILE` and friends
/// from momentary resource exhaustion — are retried indefinitely, with a backoff
/// that escalates so a condition lasting minutes is not answered with a
/// busy-wait. Only a listener that fails for a reason that will not clear (a
/// closed descriptor, say) ends the loop, and only after the capped number of
/// tries; ending it on anything less would leave the sandbox with no route to
/// the proxy for the rest of the run and, since nothing else watches the
/// listener, would do it silently.
///
/// A connection thread that cannot be *started* — `thread::Builder` reporting
/// `EAGAIN` under a low pids cgroup limit or `RLIMIT_NPROC` — is handled the
/// same way as a failed dial: it costs that one connection, not the loop. This
/// is why the spawn goes through `Builder` at all; `thread::spawn` panics on
/// that error, and the panic would unwind the accept loop and leave the sandbox
/// with no route to the proxy for the rest of the run, well before the
/// [`MAX_CONCURRENT_CONNECTIONS`] cap had a chance to apply.
pub fn serve<L: Listener, U: Upstream>(listener: L, upstream: U) {
    let live = Arc::new(AtomicUsize::new(0));
    let mut consecutive_failures: u32 = 0;
    let mut retry_pause = ACCEPT_RETRY_PAUSE;
    loop {
        let inbound = match listener.accept_one() {
            Ok(inbound) => {
                consecutive_failures = 0;
                retry_pause = ACCEPT_RETRY_PAUSE;
                inbound
            }
            Err(error) if is_recoverable(&error) => {
                // Deliberately outside the failure budget. Descriptor
                // exhaustion under load is a condition that outlasts 64 tries
                // and then goes away; counting it would end the pump for the
                // rest of the run over something that had already fixed itself.
                tracing::debug!(%error, "bridge accept failed, still listening");
                thread::sleep(retry_pause);
                retry_pause = (retry_pause * 2).min(ACCEPT_RETRY_PAUSE_MAX);
                continue;
            }
            Err(error) => {
                consecutive_failures += 1;
                if consecutive_failures >= ACCEPT_FAILURE_LIMIT {
                    tracing::warn!(
                        %error,
                        "bridge stopped accepting; the sandbox has no route to the proxy"
                    );
                    return;
                }
                // A beat before retrying. A listener that is merely in a bad
                // state may come back, and retrying 64 times in one instant
                // burst would exhaust the budget before it had the chance.
                tracing::debug!(%error, "bridge accept failed, still listening");
                thread::sleep(ACCEPT_RETRY_PAUSE);
                continue;
            }
        };

        if live.fetch_add(1, Ordering::SeqCst) >= MAX_CONCURRENT_CONNECTIONS {
            live.fetch_sub(1, Ordering::SeqCst);
            tracing::warn!("bridge is at its connection cap; dropping the newest connection");
            drop(inbound);
            continue;
        }
        let slot = ConnectionSlot(Arc::clone(&live));

        let upstream = upstream.clone();
        let started = thread::Builder::new().spawn(move || {
            let _slot = slot;
            match upstream.connect() {
                Ok(outbound) => splice(inbound, outbound),
                Err(error) => {
                    tracing::debug!(%error, "bridge could not reach its upstream");
                }
            }
        });
        if let Err(error) = started {
            // The failed `spawn` drops the closure, and with it both the
            // connection and its `ConnectionSlot` — so the slot is returned
            // here rather than counted forever against a connection that never
            // ran. A leaked slot would be permanent: nothing else decrements
            // the count, so enough of them would leave the cap refusing every
            // later connection.
            tracing::warn!(
                %error,
                "bridge could not start a connection thread; dropping the connection"
            );
            continue;
        }
    }
}

/// Copy bytes both ways until each side is done, then half-close that side.
///
/// Each direction gets its own thread because a single-threaded copy would
/// deadlock the moment a protocol has both peers waiting to read — which is
/// every protocol worth proxying.
fn splice<A: Endpoint, B: Endpoint>(a: A, b: B) {
    let (Ok(mut a_read), Ok(mut b_write)) = (a.duplicate(), b.duplicate()) else {
        return;
    };
    let mut a_write = a;
    let mut b_read = b;

    let forward = thread::spawn(move || {
        let _ = io::copy(&mut a_read, &mut b_write);
        let _ = b_write.shutdown_write();
    });

    let _ = io::copy(&mut b_read, &mut a_write);
    let _ = a_write.shutdown_write();
    let _ = forward.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[derive(Clone)]
    struct Tcp(SocketAddr);

    impl Upstream for Tcp {
        type Stream = TcpStream;

        fn connect(&self) -> io::Result<Self::Stream> {
            TcpStream::connect(self.0)
        }
    }

    /// Stand in for the proxy: echo every byte back, uppercased, so the test can
    /// tell a real round trip from a coincidence.
    fn spawn_shouting_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo server");
        let addr = listener.local_addr().expect("echo server address");
        thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                thread::spawn(move || {
                    let mut buf = Vec::new();
                    if stream.read_to_end(&mut buf).is_ok() {
                        buf.make_ascii_uppercase();
                        let _ = stream.write_all(&buf);
                    }
                });
            }
        });
        addr
    }

    #[test]
    fn a_bridged_connection_carries_bytes_both_ways() {
        let echo = spawn_shouting_echo();
        let front = TcpListener::bind("127.0.0.1:0").expect("bind bridge front door");
        let front_addr = front.local_addr().expect("bridge address");
        thread::spawn(move || serve(front, Tcp(echo)));

        let mut client = TcpStream::connect(front_addr).expect("reach the bridge");
        client.write_all(b"honmoon").expect("write through bridge");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("half-close so the echo server sees EOF");

        let mut reply = String::new();
        client.read_to_string(&mut reply).expect("read the reply");
        assert_eq!(
            reply, "HONMOON",
            "the bridge must carry bytes to the upstream and the answer back"
        );
    }

    /// A listener that refuses a fixed number of times before behaving, standing
    /// in for `ECONNABORTED` / `EMFILE` — failures that are about one client, not
    /// about the listener.
    ///
    /// The failure is supplied by the caller because the two cases differ in how
    /// they reach the pump: `ECONNABORTED` arrives as an `io::ErrorKind`, while
    /// `EMFILE` has no kind of its own and is only visible as a raw errno.
    struct Flaky {
        inner: TcpListener,
        remaining_failures: std::sync::Mutex<u32>,
        failure: fn() -> io::Error,
    }

    impl Listener for Flaky {
        type Stream = TcpStream;

        fn accept_one(&self) -> io::Result<Self::Stream> {
            {
                let mut remaining = self.remaining_failures.lock().expect("failure counter");
                if *remaining > 0 {
                    *remaining -= 1;
                    return Err((self.failure)());
                }
            }
            self.inner.accept().map(|(stream, _)| stream)
        }
    }

    #[test]
    fn a_transient_accept_failure_does_not_stop_the_accept_loop() {
        let echo = spawn_shouting_echo();
        let front = TcpListener::bind("127.0.0.1:0").expect("bind bridge front door");
        let front_addr = front.local_addr().expect("bridge address");
        let flaky = Flaky {
            inner: front,
            remaining_failures: std::sync::Mutex::new(5),
            failure: || io::Error::from(io::ErrorKind::ConnectionAborted),
        };
        thread::spawn(move || serve(flaky, Tcp(echo)));

        let mut client = TcpStream::connect(front_addr).expect("reach the bridge");
        client.write_all(b"honmoon").expect("write through bridge");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("half-close so the echo server sees EOF");

        let mut reply = String::new();
        client.read_to_string(&mut reply).expect("read the reply");
        assert_eq!(
            reply, "HONMOON",
            "an aborted handshake concerns one client; ending the accept loop on \
             it would leave the sandbox with no route to the proxy at all"
        );
    }

    #[test]
    fn sustained_resource_pressure_does_not_end_the_accept_loop() {
        let echo = spawn_shouting_echo();
        let front = TcpListener::bind("127.0.0.1:0").expect("bind bridge front door");
        let front_addr = front.local_addr().expect("bridge address");
        // Comfortably more failures than the budget a *permanent* listener
        // failure gets: descriptor exhaustion that lasts longer than 64 tries
        // and then clears is ordinary under load, and must not be the thing that
        // ends the pump.
        let flaky = Flaky {
            inner: front,
            remaining_failures: std::sync::Mutex::new(100),
            failure: || io::Error::from_raw_os_error(libc::EMFILE),
        };
        thread::spawn(move || serve(flaky, Tcp(echo)));

        let mut client = TcpStream::connect(front_addr).expect("reach the bridge");
        client.write_all(b"honmoon").expect("write through bridge");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("half-close so the echo server sees EOF");

        let mut reply = String::new();
        client.read_to_string(&mut reply).expect("read the reply");
        assert_eq!(
            reply, "HONMOON",
            "descriptor exhaustion clears on its own, so it must be retried \
             rather than counted against the budget that ends the pump"
        );
    }

    #[test]
    fn one_unreachable_upstream_does_not_stop_the_accept_loop() {
        // A port nobody is listening on: reserve one, then drop the listener.
        let dead = {
            let probe = TcpListener::bind("127.0.0.1:0").expect("reserve a port");
            probe.local_addr().expect("reserved address")
        };
        let front = TcpListener::bind("127.0.0.1:0").expect("bind bridge front door");
        let front_addr = front.local_addr().expect("bridge address");
        thread::spawn(move || serve(front, Tcp(dead)));

        // First connection cannot be spliced anywhere and is dropped.
        let mut doomed = TcpStream::connect(front_addr).expect("reach the bridge");
        let _ = doomed.write_all(b"lost");
        let mut discarded = Vec::new();
        let _ = doomed.read_to_end(&mut discarded);

        // The loop has to still be there for the next one.
        let survivor = TcpStream::connect(front_addr);
        assert!(
            survivor.is_ok(),
            "a failed upstream dial must not take the accept loop down with it"
        );
    }
}
