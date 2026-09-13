//! The dependency boundary `crates/AGENTS.md` draws around this crate (issue #166).
//!
//! This covers only the part of that section's forbidden list which genuinely needs
//! a new crate: an async runtime, and an HTTP client such as `hyper` or `reqwest`.
//! It does **not** cover the rest. An environment read, a spawned process and a
//! second open file reach through `std`; so does a socket, via `std::net` or the
//! `socket`/`connect`/`bind` that the already-present `libc` exposes. None of them
//! moves the manifest, so this test stays green for all of them. Do not cite it as
//! enforcement of those — this file itself spawns a process and reads an
//! environment variable, which is the point.
//!
//! The boundary is a property of the *manifest*, so it is read from `cargo
//! metadata` — cargo's own resolution of the dependency tables, which is the only
//! reading that includes `[target.'cfg(unix)'.dependencies]`. That table is where
//! `libc` lives, and it is exactly where a scan of `Cargo.toml` written by hand
//! would miss an addition.
//!
//! `[dev-dependencies]` are deliberately out of scope. The audit-sink suite already
//! builds FIFO fixtures with `libc::mkfifo` and spawns threads, and nothing it links
//! reaches a shipped binary; the boundary is about what `honmoon-core` *is*, not
//! about how it is exercised.

/// Every crate `honmoon-core` builds against today.
///
/// This is a record of the current dependency set, not a second copy of the rule —
/// the rule lives in `crates/AGENTS.md` under Boundaries, and only there. A change
/// here means the set moved and someone should read that rule; it does not mean the
/// rule is written out below.
const BUILD_DEPENDENCIES: &[&str] = &[
    "aho-corasick",
    "cel",
    "hmac",
    "libc",
    "percent-encoding",
    "regex",
    "serde",
    "serde_json",
    "serde_yaml",
    "sha2",
    "sqlparser",
    "thiserror",
    "time",
    "tracing",
];

#[test]
fn the_manifest_gains_no_dependency_without_a_look_at_the_boundary() {
    let metadata = cargo_metadata();
    let package = metadata["packages"]
        .as_array()
        .expect("cargo metadata lists packages")
        .iter()
        .find(|p| p["name"] == "honmoon-core")
        .expect("honmoon-core is one of them");

    let mut current: Vec<&str> = package["dependencies"]
        .as_array()
        .expect("a package lists its dependencies")
        // `kind` is absent (JSON `null`) for a normal dependency and carries
        // `"dev"` or `"build"` otherwise. Build dependencies are held to the same
        // boundary; dev-dependencies are not, for the reason the module doc gives.
        .iter()
        .filter(|d| d["kind"] != "dev")
        .map(|d| d["name"].as_str().expect("a dependency is named"))
        .collect();
    current.sort_unstable();
    current.dedup();

    let mut expected: Vec<&str> = BUILD_DEPENDENCIES.to_vec();
    expected.sort_unstable();

    assert_eq!(
        current, expected,
        "\nhonmoon-core's build dependencies moved.\n\n\
         Before updating BUILD_DEPENDENCIES to match, read the Boundaries section of \
         crates/AGENTS.md: this crate takes no async runtime, no sockets, and no network \
         or HTTP client, and the single file it opens is the audit JSONL sink in \
         `audit.rs`. A dependency that brings any of those is the change that section \
         forbids, and adding it to the list below does not make it allowed.\n"
    );
}

/// Ask cargo what this crate depends on. `--no-deps` keeps it to the workspace's own
/// manifests, so the answer needs no network and no resolution of the wider graph.
fn cargo_metadata() -> serde_json::Value {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = std::process::Command::new(cargo)
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .arg("--manifest-path")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .output()
        .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cargo metadata emits JSON")
}
