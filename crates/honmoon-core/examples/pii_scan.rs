//! Benchmark bridge: read EvalRecord JSONL on stdin, emit predictions JSONL on
//! stdout. Each record's `spans` are replaced with honmoon-core Tier-1
//! detections so the TS scorer can measure precision / recall / F1.
//!
//! ```sh
//! cargo run -q -p honmoon-core --example pii_scan < gold.jsonl > pred.jsonl
//! bun datasets/pii/score.ts gold.jsonl pred.jsonl
//! ```
//!
//! Only `spans` is rewritten; `id`/`source`/`surface`/`lang`/`text`/`meta` are
//! passed through unchanged so the scorer can match gold and pred by `id`.

use std::io::{self, BufRead, Write};

use honmoon_core::detect_spans;

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let mut rec: serde_json::Value = serde_json::from_str(&line)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let text = rec.get("text").and_then(|v| v.as_str()).unwrap_or_default();
        let spans = detect_spans(text);
        rec["spans"] = serde_json::to_value(&spans).map_err(io::Error::other)?;
        writeln!(out, "{}", serde_json::to_string(&rec)?)?;
    }
    out.flush()
}
