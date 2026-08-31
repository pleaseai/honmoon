//! Enforced `honmoon run` isolation on macOS: a Seatbelt profile that leaves the
//! child exactly one reachable socket — the ephemeral proxy on loopback
//! (ADR-0005).
//!
//! This path is far smaller than the Linux one, and the reason is worth stating
//! rather than leaving to be noticed. Linux replaces the child's *network
//! namespace*, which puts the child and the proxy on two different loopbacks and
//! forces a Unix-socket pump between them. Seatbelt replaces nothing: the child
//! keeps the host's loopback, where honmoon's proxy is already listening. So
//! there is no bridge, no scratch directory, and no re-exec through a supervisor
//! — the profile's entire job is to take away every *other* socket.
//!
//! The mechanism is `sandbox-exec`, which ships with macOS. No system extension,
//! no `NetworkExtension` entitlement, no signing, notarization, app bundle or
//! install-time approval, and so no dependency on Apple Developer Program
//! membership. `anthropic-experimental/sandbox-runtime` — the sandbox behind
//! Claude Code — confines egress the same way.
//!
//! # What the profile allows, and why
//!
//! `(allow default)` first, then `(deny network*)`, then a short list of things
//! handed back. Seatbelt is last-match-wins, so the order is the policy.
//!
//! - **The filesystem is left alone, deliberately.** honmoon's remit is egress.
//!   A profile that also policed reads and writes would be making a containment
//!   claim this product does not test, cannot tune per policy, and would break
//!   ordinary tools to honour. `srt` restricts the filesystem in the same
//!   profile; honmoon does not, and that is a choice rather than an omission.
//! - **One remote address: the proxy.** `remote ip` matches the port as well as
//!   the host, so a neighbouring service on loopback stays unreachable — which
//!   the integration suite asserts by putting an origin server there.
//! - **Filesystem `AF_UNIX` sockets stay reachable**, matching Linux, where only
//!   the network namespace is replaced. On both platforms this is a *documented
//!   escape* rather than an oversight: a local daemon behind a socket
//!   (`/var/run/docker.sock` and friends) will still act on the child's behalf.
//!   Keep such sockets away from the uid you run under.
//! - **Except the system resolver.** `mDNSResponder` is one of those daemons,
//!   and it is a route off the machine that an empty network namespace does not
//!   have: a hostname is a message, and the resolver will carry it. Denying its
//!   socket puts macOS level with Linux, where a child in an empty namespace
//!   cannot resolve either. A proxied client does not need DNS — it hands the
//!   proxy a name and the proxy resolves it.
//!
//! # Limits, stated rather than discovered
//!
//! - The resolver rule is **defence in depth, not a boundary**. The path is
//!   Apple's to move, and if it moves the rule silently stops matching. What it
//!   can never do is hand back a TCP route; that is the `deny network*` above,
//!   which names an operation rather than a path.
//! - Seatbelt's `remote ip` filter accepts only `*` or `localhost` as a host —
//!   a literal `127.0.0.1` is rejected by the profile compiler — and `localhost`
//!   covers `::1` as well as `127.0.0.1`. The hole is therefore two addresses
//!   wide, so `run` binds the proxy on **both** loopback families at one port
//!   (`bind_loopback_pair` in `main.rs`) rather than on IPv4 alone. Without
//!   that, an unrelated process holding the same port number on `::1` would be
//!   sitting inside the one exception this profile makes, reachable by the child
//!   with no policy in the way.
//! - The child shares the host's loopback, so a listener it binds there is
//!   visible to other processes on this machine. Under Linux that loopback is
//!   private to the namespace. Nothing off-box can reach it on either platform.
//! - As on Linux, a **connected network socket handed to `honmoon` as its own
//!   stdin, stdout or stderr** is inherited by the child and stays a live
//!   channel to that one peer. The child needs those three descriptors to be a
//!   usable command at all. This needs an operator to have wired honmoon's stdio
//!   to a network peer; it is not something the child can arrange.
//! - **A descendant that outlives `run` keeps an exception to a port `run` no
//!   longer owns.** `Command::status` waits for the *direct* child, so a command
//!   that daemonizes returns immediately and `run` exits, closing both loopback
//!   listeners — while the surviving descendant still carries the profile, and
//!   its one TCP exception still names `localhost:<proxy_port>`. That port is
//!   now free, the descendant can read the number out of its own environment,
//!   and whatever local process binds it next is an off-policy relay.
//!
//!   Linux does not have this, and the asymmetry is structural rather than an
//!   oversight here: there the child is in an empty namespace, so when the
//!   bridge dies nothing off-box is reachable from inside it no matter who else
//!   is on the host. Seatbelt leaves the child on the *host* loopback, so the
//!   boundary lasts only as long as honmoon owns a host resource.
//!
//!   The fix is to hold the listeners for the sandbox's lifetime rather than the
//!   direct child's — the child in its own process group, sockets held while
//!   `kill(-pgid, 0)` still succeeds. It is not done here because it changes
//!   what `run` is: it would stop returning when the command it was given
//!   returns, so a command that spawns a daemon would block. That is an
//!   ADR-0005 amendment, not a detail. Tracked under TD-003, which this file
//!   does not close.
//! - `sandbox-exec` is formally deprecated by Apple. It is what Claude Code
//!   ships on today, so it is serviceable, but the deprecation is real. If Apple
//!   removes it, the `NETransparentProxyProvider` design in the history of #69
//!   is the fallback.

use std::io;
use std::net::SocketAddr;
use std::process::{Command, ExitStatus, Stdio};

/// Absolute rather than resolved through `PATH`.
///
/// `run` inherits its environment from whoever launched it, so a `PATH` entry
/// under someone else's control would otherwise choose what "the sandbox" is —
/// and a `sandbox-exec` that simply execs its argument would leave the child
/// unconfined while every message still said `Enforced`.
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// Where the kernel lists this process's open descriptors.
const DEV_FD: &str = "/dev/fd";

/// stdin, stdout and stderr — the three the child keeps.
const STDIO_DESCRIPTORS: libc::c_int = 3;

/// A port no run will use, for compiling the profile during the probe.
///
/// Only its syntax matters there; nothing binds it.
const PROBE_PORT: u16 = u16::MAX;

/// Can this host actually confine a child?
///
/// Asks the mechanism rather than the filesystem, and asks it with **the real
/// profile** rather than a trivial one. That second part is the point: the
/// deprecation warning on `sandbox-exec` is not theoretical, and the failure it
/// would arrive as is a dialect change — `path-literal` dropped, `unix-socket`
/// renamed — that a `(version 1)(allow default)` probe would sail straight
/// through while every real run failed. Compiling the profile honmoon actually
/// uses turns that into an advisory downgrade with a warning, which is the
/// documented behaviour, instead of a run that dies with a compiler backtrace.
///
/// It also means the only thing that varies between here and [`run_confined`]
/// is a `u16` rendered by `format!`, so a profile that compiles now compiles
/// then.
pub fn sandbox_available() -> bool {
    Command::new(SANDBOX_EXEC)
        .arg("-p")
        .arg(profile(PROBE_PORT))
        .arg("--")
        .arg("/usr/bin/true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Run `program` under a Seatbelt profile that leaves only `proxy` reachable.
///
/// Returns the command's own exit status. `Err` means the sandbox could not be
/// set up and the command has **not** run, which is what lets the caller fall
/// back to advisory without any risk of running it twice.
pub fn run_confined(proxy: SocketAddr, program: &str, args: &[String]) -> io::Result<ExitStatus> {
    // The profile can only name `localhost`, so a proxy anywhere else would be
    // unreachable from inside it and every child would fail to connect. `run`
    // binds `127.0.0.1:0`, so this is unreachable in practice — it is here so
    // that if it ever stops being true, the run downgrades to advisory with a
    // stated reason instead of confining children into a dead end.
    if !proxy.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "the egress proxy is on {proxy}, but a Seatbelt profile can only \
                 open a hole to loopback"
            ),
        ));
    }

    // Before the spawn, and propagated rather than swallowed: a descriptor that
    // survives into the child is a channel the profile never sees, so failing to
    // secure them means this is not the boundary it claims to be. An `Err` here
    // downgrades the run to advisory with a stated reason, which is the honest
    // outcome.
    close_inherited_descriptors_on_exec()?;

    let mut command = Command::new(SANDBOX_EXEC);
    // `--` because `program` comes from the user's command line: without it a
    // command whose name begins with a dash would be read as an option to
    // `sandbox-exec` rather than as the thing to confine.
    command
        .arg("-p")
        .arg(profile(proxy.port()))
        .arg("--")
        .arg(program)
        .args(args);

    let proxy_url = format!("http://{proxy}");
    for (key, value) in super::proxy_env(&proxy_url) {
        command.env(key, value);
    }
    // Cleared rather than replaced, which is the opposite of what the Linux
    // supervisor does, and for a reason that does not carry over. There, the
    // child's `127.0.0.1` is a *different* loopback from the host's, so
    // loopback has to stay direct or a request for it would be bridged out and
    // answered by another machine's worth of services. Here the child is on the
    // host's loopback and Seatbelt has already taken it away, so an exemption
    // buys nothing: with `no_proxy` set, a client asking for a loopback address
    // dials it directly and is refused by the kernel; with it cleared, the same
    // request goes to the proxy and gets a policy verdict. An inherited
    // `no_proxy` is worse still — it carves holes in policy that the operator
    // meant for a context this one is not.
    command.env_remove("no_proxy").env_remove("NO_PROXY");

    // `sandbox-exec` applies the profile and then `exec`s, so this status is the
    // command's own. A profile that failed to compile would exit 65 here without
    // running anything — indistinguishable from a child that chose to exit 65 —
    // but `sandbox_available()` compiled this exact profile moments ago and the
    // only thing that has changed since is a `u16` rendered by `format!`.
    command.status()
}

/// Make every descriptor above stdio close on `exec`.
///
/// Seatbelt gates `connect`, not writes on a socket that is *already* connected,
/// so an inherited descriptor is a route the profile can never see. If whoever
/// launched `honmoon` left a connected socket open above stderr without
/// `FD_CLOEXEC` — a supervisor, a shell redirect — the confined command inherits
/// it and talks to that peer with no policy in the way. The Linux path closes
/// these in `supervise`; this is the same boundary drawn the same place.
///
/// Marked rather than closed, and in the parent rather than in a `pre_exec`
/// hook, because both alternatives break something. Closing here would take
/// honmoon's own proxy listeners with it. Closing in the hook would take the
/// `CLOEXEC` pipe `Command` uses to report a failed `exec`, which would make a
/// failed spawn look like a successful one — the reason the Linux sweep happens
/// after its second `exec` rather than between fork and exec. `FD_CLOEXEC` costs
/// the parent nothing: it only decides what survives the `exec`.
///
/// Descriptors opened *after* this runs are not a gap. The sweep exists for
/// descriptors honmoon inherited, which cannot appear later, and everything Rust
/// opens is `CLOEXEC` from birth.
///
/// stdio is left alone — the child needs a stdin, stdout and stderr to be a
/// usable command at all, which is the documented exception at the top of this
/// file.
fn close_inherited_descriptors_on_exec() -> io::Result<()> {
    for fd in open_descriptors()? {
        if fd < STDIO_DESCRIPTORS {
            continue;
        }
        // SAFETY: `fcntl` with `F_GETFD`/`F_SETFD` reads and writes one flag on
        // a descriptor number and touches no memory of ours.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags < 0 {
                skip_if_already_gone(fd)?;
                continue;
            }
            if flags & libc::FD_CLOEXEC == 0 {
                // Variadic, so the argument is passed as exactly the type given
                // — Rust does not promote it to `int` the way C would.
                if libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
                    skip_if_already_gone(fd)?;
                }
            }
        }
    }
    Ok(())
}

/// Swallow an `EBADF` from the sweep and report anything else.
///
/// `EBADF` is the one failure that is not a failure: the descriptor is gone,
/// which is a stronger version of what the sweep was trying to achieve. It is
/// reachable in normal operation — the directory handle `open_descriptors` used
/// is itself listed and then closed, and the proxy thread is already accepting
/// connections while this runs, so a descriptor can close between the listing
/// and the `fcntl`.
///
/// Every other errno means a descriptor that may still cross the `exec`
/// unmarked, and the caller must not report enforcement over it.
fn skip_if_already_gone(fd: libc::c_int) -> io::Result<()> {
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EBADF) {
        return Ok(());
    }
    Err(io::Error::new(
        error.kind(),
        format!("descriptor {fd} could not be marked close-on-exec: {error}"),
    ))
}

/// The descriptors this process is actually holding, read from `/dev/fd`.
///
/// Asks the kernel what is open rather than walking `0..RLIMIT_NOFILE`, and the
/// difference is correctness before it is speed. The soft limit is not an upper
/// bound on descriptor *numbers*: a launcher that opened a descriptor and then
/// lowered `RLIMIT_NOFILE` leaves it open above the new limit, where a bounded
/// sweep never looks and Seatbelt cannot help — the profile only gates
/// `connect`, and that peer is already connected. Verified rather than reasoned
/// about: with a descriptor duplicated to 100 and the soft limit then set to 20,
/// `/dev/fd` still lists 100.
///
/// It is also the difference between one `getdirentries` and a million `fcntl`
/// calls — stock macOS hands `honmoon` a soft limit of 1048576.
///
/// An unreadable `/dev/fd` is an error rather than a fallback to the bounded
/// sweep. This is `devfs`, present on every macOS install; if it cannot be read,
/// this is not the system this module reasons about, and reporting success over
/// a sweep that did not happen is exactly the overstatement it exists to avoid.
/// The caller turns the error into an announced downgrade to advisory.
fn open_descriptors() -> io::Result<Vec<libc::c_int>> {
    let mut open = Vec::new();
    for entry in std::fs::read_dir(DEV_FD)? {
        let name = entry?.file_name();
        let fd = name
            .to_str()
            .and_then(|name| name.parse::<libc::c_int>().ok())
            .ok_or_else(|| {
                io::Error::other(format!(
                    "{DEV_FD} holds {name:?}, which is not a descriptor number, \
                     so the descriptors this process may have inherited \
                     cannot be enumerated"
                ))
            })?;
        open.push(fd);
    }
    Ok(open)
}

/// The Seatbelt profile, as a single argument to `sandbox-exec -p`.
///
/// Built inline rather than written to a file: the Linux path's scratch
/// directory produced a whole class of bugs — a squattable name, a `sun_path`
/// overflow, a umask that stripped the owner bits — and none of them can exist
/// for a string that never touches the filesystem. `proxy_port` is a `u16`
/// rendered by `format!`, so there is nothing here to inject into.
fn profile(proxy_port: u16) -> String {
    format!(
        r#"(version 1)

;; Seatbelt is last-match-wins, so this file reads top to bottom as: everything,
;; then no sockets, then these sockets.

;; The filesystem, processes and IPC are left exactly as they were. honmoon's
;; remit is egress; policing reads and writes here would claim a containment
;; this product does not test and cannot express in a policy.
(allow default)

;; Take away every socket the child could open, in any address family.
(deny network*)

;; Hand back exactly one remote address: honmoon's ephemeral proxy. The filter
;; matches the port too, so the rest of loopback stays unreachable. `localhost`
;; is not a convenience spelling — the profile compiler rejects a literal IP.
(allow network-outbound (remote ip "localhost:{proxy_port}"))

;; Filesystem AF_UNIX sockets stay reachable, matching Linux, where only the
;; network namespace is replaced. A documented escape on both platforms: a local
;; daemon behind a socket still acts on the child's behalf.
(allow network-bind network-outbound (local unix-socket))
(allow network-outbound (remote unix-socket))

;; Except the resolver, which is such a daemon and is also a route off the
;; machine that an empty network namespace does not have. A proxied client does
;; not need it: it hands the proxy a name and the proxy resolves it.
(deny network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn the_profile_opens_the_proxy_port_and_nothing_else_on_the_network() {
        let text = profile(41234);
        assert!(
            text.contains(r#"(deny network*)"#),
            "the profile has to start from no sockets at all, or the allow below \
             is an addition to the host's network rather than a replacement for \
             it:\n{text}"
        );
        assert!(
            text.contains(r#"(allow network-outbound (remote ip "localhost:41234"))"#),
            "the proxy's exact port must be the hole, not a wildcard:\n{text}"
        );
        assert!(
            !text.contains(r#"remote ip "*"#),
            "a wildcard remote would hand back the whole network the deny above \
             just took away:\n{text}"
        );
    }

    #[test]
    fn the_profile_denies_the_resolver_after_allowing_unix_sockets() {
        let text = profile(1024);
        let allow = text
            .find("(allow network-outbound (remote unix-socket))")
            .expect("filesystem Unix sockets stay reachable, matching Linux");
        let deny = text
            .find("mDNSResponder")
            .expect("the resolver is a route off the machine that Linux does not have");
        assert!(
            deny > allow,
            "Seatbelt is last-match-wins: a resolver deny placed above the \
             blanket Unix-socket allow is overridden by it, and DNS quietly comes \
             back:\n{text}"
        );
    }

    #[test]
    fn a_proxy_off_loopback_is_refused_rather_than_confined_into_a_dead_end() {
        let off_box = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
        let error = run_confined(off_box, "/usr/bin/true", &[])
            .expect_err("a profile cannot open a hole to anything but loopback");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn a_descriptor_left_open_by_the_launcher_does_not_survive_the_exec() {
        use std::os::unix::io::AsRawFd;

        // Stands in for a socket a supervisor left open above stderr: a real
        // descriptor with `FD_CLOEXEC` deliberately cleared.
        let inherited = std::fs::File::open("/dev/null").expect("open /dev/null");
        let fd = inherited.as_raw_fd();
        // SAFETY: clearing and reading one flag on a descriptor this test owns.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
        }

        close_inherited_descriptors_on_exec().expect("sweep the descriptor table");

        // SAFETY: reading one flag on a descriptor this test owns.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(
            flags & libc::FD_CLOEXEC != 0,
            "a descriptor honmoon inherited would have crossed the exec into \
             the sandbox, where an already-connected socket is a route the \
             Seatbelt profile never gets to see"
        );
    }

    /// Set on the re-exec below, so the child knows to run the fixture rather
    /// than fork again.
    const LOWERED_LIMIT_FIXTURE: &str = "HONMOON_TEST_LOWERED_DESCRIPTOR_LIMIT";

    /// The test to run in that child. `--exact` needs the full path.
    const LOWERED_LIMIT_TEST: &str =
        "isolate::macos::tests::a_descriptor_above_a_lowered_limit_is_still_marked";

    /// Printed by the fixture, checked by the parent.
    ///
    /// libtest exits 0 when a filter matches nothing, so a renamed test would
    /// make the child run *no* tests, exit successfully, and pass this by
    /// checking nothing — the silent pass this whole file argues against.
    const LOWERED_LIMIT_RAN: &str = "the lowered-limit fixture ran";

    /// A launcher may open a descriptor and *then* lower `RLIMIT_NOFILE`,
    /// leaving it open above the new limit. The bounded `3..RLIMIT_NOFILE` walk
    /// this replaced would not have looked there, and Seatbelt cannot cover for
    /// it: the profile gates `connect`, and that peer is already connected.
    ///
    /// So the fixture builds that exact state — descriptor first, lowered limit
    /// second — rather than just parking a descriptor at a high number, which a
    /// bounded walk would have reached anyway (stock macOS allows 1048576).
    ///
    /// And it builds it in a process of its own, because `RLIMIT_NOFILE` is
    /// process-wide while libtest runs tests on threads: a sibling test that
    /// opens a file during the window would fail with `EMFILE` over something
    /// neither test is about. Re-exec is the cheapest isolation available here —
    /// `fork` would have to survive `read_dir` allocating in a threaded child,
    /// which is not a promise `malloc` makes.
    #[test]
    fn a_descriptor_above_a_lowered_limit_is_still_marked() {
        use std::os::unix::io::AsRawFd;

        if std::env::var_os(LOWERED_LIMIT_FIXTURE).is_none() {
            let binary = std::env::current_exe().expect("the running test binary");
            let output = Command::new(binary)
                .args(["--exact", LOWERED_LIMIT_TEST, "--nocapture"])
                .env(LOWERED_LIMIT_FIXTURE, "1")
                .output()
                .expect("re-exec the test binary to isolate the fixture");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains(LOWERED_LIMIT_RAN),
                "the fixture never ran — {LOWERED_LIMIT_TEST} no longer names a \
                 test, so this was passing without checking anything.\n{stdout}\
                 {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                output.status.success(),
                "the fixture failed in its own process:\n{stdout}{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        println!("{LOWERED_LIMIT_RAN}");

        let inherited = std::fs::File::open("/dev/null").expect("open /dev/null");
        // `F_DUPFD` (not `F_DUPFD_CLOEXEC`) hands back the lowest free
        // descriptor at or above the floor, with `FD_CLOEXEC` clear — the
        // fixture and a high number in one call.
        // SAFETY: duplicating a descriptor this test owns.
        let sparse = unsafe { libc::fcntl(inherited.as_raw_fd(), libc::F_DUPFD, 500) };
        assert!(sparse >= 500, "F_DUPFD: {}", io::Error::last_os_error());

        let mut original = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `getrlimit` fills the struct it is handed.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut original) },
            0,
            "getrlimit: {}",
            io::Error::last_os_error()
        );
        let lowered = libc::rlimit {
            rlim_cur: sparse as libc::rlim_t,
            rlim_max: original.rlim_max,
        };
        // SAFETY: `setrlimit` reads the struct it is handed. Lowering the soft
        // limit does not close descriptors already above it — that is the point.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) },
            0,
            "setrlimit: {}",
            io::Error::last_os_error()
        );

        let swept = close_inherited_descriptors_on_exec();

        // SAFETY: reading one flag on a descriptor this process owns, closing
        // it, and restoring a limit this process lowered. Done before the
        // assertions so the state is unwound whether or not they hold.
        let flags = unsafe { libc::fcntl(sparse, libc::F_GETFD) };
        let restored = unsafe {
            libc::close(sparse);
            libc::setrlimit(libc::RLIMIT_NOFILE, &original)
        };

        assert_eq!(restored, 0, "restoring RLIMIT_NOFILE");
        swept.expect("sweep the descriptor table");
        assert!(
            flags & libc::FD_CLOEXEC != 0,
            "descriptor {sparse} sits above the soft limit and crossed the exec \
             unmarked — the sweep is reading a bound rather than the descriptor \
             table, so a launcher that lowered RLIMIT_NOFILE after opening a \
             socket would hand the confined child a live connection to its peer"
        );
    }

    /// The profile is generated, so a dialect change is the realistic way it
    /// breaks — and it would break silently, as an advisory downgrade, if the
    /// probe compiled something simpler than the real thing.
    #[test]
    fn the_real_profile_compiles_on_this_host() {
        assert!(
            sandbox_available(),
            "every macOS host ships /usr/bin/sandbox-exec, so a failure here \
             means the profile no longer compiles — the SBPL dialect moved and \
             `honmoon run` has silently gone advisory on this OS version"
        );
    }
}
