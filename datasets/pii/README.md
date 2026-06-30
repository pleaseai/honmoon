# PII benchmark dataset

Evaluation data + tooling for **Phase 5 — Content-aware PII / DLP**.
Goals, metrics, and targets: [`docs/pii-benchmark-goals.md`](../../docs/pii-benchmark-goals.md).

## Layout

```
datasets/pii/
  schema.json            # unified eval record JSON Schema (the one format the scorer consumes)
  labels.yaml            # 33 canonical PII labels + ko-pii / Presidio / KDPII mapping (source of truth)
  build/                 # dataset builders (Bun + TypeScript)
    types.ts             #   shared types + labels.yaml loader
    synth_values.ts      #   deterministic, checksum-valid fake value generators (+ validators)
    normalize_kdpii.ts   #   KDPII test.json → unified records
    gen_synth.ts         #   positive records: valid PII across wire surfaces
    gen_negative.ts      #   hard negatives: PII-shaped non-PII (precision probe)
  score.ts               # entity-level P/R/F1 scorer (ko-pii match_forms_overlap rule)
  raw/   (gitignored)    # downloaded corpora
  eval/  (gitignored)    # build outputs (dev.jsonl / test.jsonl)
```

## Build

```bash
# 1. KDPII (Zenodo 10968609, CC-BY-4.0) — download once into raw/kdpii/
mkdir -p raw/kdpii && for s in train valid test; do
  curl -sL "https://zenodo.org/api/records/10968609/files/$s.json/content" -o "raw/kdpii/$s.json"
done

# 2. Normalize + generate (→ eval/)
mkdir -p eval
bun build/normalize_kdpii.ts raw/kdpii/test.json  test  > eval/kdpii-test.jsonl
bun build/normalize_kdpii.ts raw/kdpii/valid.json valid > eval/kdpii-valid.jsonl   # → dev
bun build/gen_synth.ts    > eval/honmoon-synth.jsonl
bun build/gen_negative.ts > eval/honmoon-negative.jsonl
```

## Score

`score.ts` compares a gold JSONL against a prediction JSONL (same `id`s), both in the unified
schema. Detectors (the Rust Tier-1/2 engine) are Phase 5 work; until then, self-scoring gold↔gold
validates the harness (micro-F1 = 1.000).

```bash
bun score.ts eval/kdpii-test.jsonl <predictions.jsonl>
```

## Notes

- **No real PII is stored.** `gen_synth` emits format/checksum-valid but non-existent values.
- KDPII `begin`/`end` are code-point offsets; for BMP Korean they equal the UTF-16 offsets the
  schema uses.
- `labels.yaml` is the single source of truth — `types.ts` indexes it at runtime.
