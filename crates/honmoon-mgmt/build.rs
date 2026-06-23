//! Ensure the embedded-dashboard folder exists at compile time.
//!
//! `rust-embed` requires `apps/dashboard/dist` to exist when the macro expands,
//! but `dist/` is a build artifact (gitignored) and may be absent on a clean
//! checkout that hasn't run `vite build`. Drop a placeholder `index.html` so a
//! bare `cargo build` always succeeds; a real `bun run --filter
//! @honmoon/dashboard build` overwrites it with the actual dashboard.

use std::path::PathBuf;

const PLACEHOLDER: &str = r#"<!doctype html>
<html lang="en">
  <head><meta charset="utf-8" /><title>Honmoon</title></head>
  <body>
    <p>Dashboard not built. Run
      <code>bun run --filter @honmoon/dashboard build</code>
      then rebuild the binary.</p>
  </body>
</html>
"#;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let dist = manifest.join("../../apps/dashboard/dist");
    let index = dist.join("index.html");
    if !index.exists() {
        let _ = std::fs::create_dir_all(&dist);
        let _ = std::fs::write(&index, PLACEHOLDER);
    }
    println!("cargo:rerun-if-changed={}", dist.display());
}
