# Honmoon — PII Detection Benchmark Goals

> Status: Draft (v0.1) · Last updated: 2026-06-30
>
> Defines the evaluation methodology and target numbers for **content-aware PII detection / DLP**
> in Honmoon — the acceptance criteria for **Phase 5** of the roadmap.
> Related: [`roadmap.md#phase-5`](./roadmap.md) · [`.please/docs/knowledge/product.md`](../.please/docs/knowledge/product.md)

## 1. Background — why PII detection

The core problem in `product.md` is **unintended data exfiltration by AI agents**.
Today Honmoon controls *where / what protocol* traffic goes (domain allowlist +
SQL/K8s/HTTP parsing) but never inspects **what is inside the request body**. To catch
a resident registration number, card number, or account number being shipped to an
external endpoint, we need content-level PII detection.

This feeds a new input into the verdict pipeline: detection results become CEL facts
(`pii.types`, `pii.count`, `pii.max_severity`, …) that drive `allow` / `deny` / `pause`.

## 2. Design constraint — inline data plane

Honmoon's PII detection runs **on the request path (inline)**. It is not an offline batch
scanner. This constraint dominates tool choice and targets.

| Tool | Approach | Speed (per doc) | Korean | Inline fit |
|------|----------|------|--------|------|
| **ko-pii** | Rules + dictionaries + checksums (no ML) | **0.19 ms** | ★★★ | ✅ fits |
| Presidio | Regex + spaCy/Transformers NER | 4.2 ms | ★ (KR recognizers exist, off by default) | △ only with NER disabled |
| openai/privacy-filter | LLM (660M) | 481 ms | ★★ | ❌ unfit |

→ **Conclusion**: the primary detection layer must be **native Rust regex + checksums**
   (porting the ko-pii approach to Rust). NER/ML stays an **optional, asynchronous layer**
   for accuracy boosting only (audit mode, or scoring `pause` candidates).
   Source: ko-pii `docs/BENCHMARK.md` speed measurements.

## 3. Evaluation datasets

| Dataset | Size | Language | License | Role |
|---------|------|----------|---------|------|
| **KDPII** (Yonsei Hansaem Kim Lab, IEEE Access 2024, Zenodo `10968609`) | official `train`/`valid`/`test`; test = 4,891 docs / 2,211 gold spans / 33 labels | Korean (dialogic) | CC-BY-4.0 | **Primary eval set** (real-data lineage) — use official splits as-is |
| **ko-pii synthetic eval** (`generated_eval.jsonl`) | 540 docs / 3,635 gold spans / 26 labels | Korean (administrative/form style) | MIT | Per-label & regression |
| ko-pii extended (`generated_eval_large.jsonl`) | 1,938 docs | Korean | MIT | Stability & bulk regression |
| **PII-Bench** (Fudan, arXiv 2502.18545) | Test-Hard 200 + Test-Distract 200 (2,842 total) | English | Unknown (unconfirmed) | **Future** query-aware masking reference |

Notes:
- KDPII and the ko-pii synthetic set use **different label schemes** (KDPII = its own 33
  labels like `OG_WORKPLACE`; ko-pii = its own 33 categories). A **label-mapping table**
  must be fixed first for any comparison to be valid.
- PII-Bench is English plus a harder task ("preserve PII the query needs, mask only what it
  doesn't"). It diverges from Honmoon v1's simple detect/block, so keep it as a reference for
  the **long-term goal (context-aware masking)** only.
- **Conversational vs form-like is the dominant axis** (ko-pii `BENCHMARK.md`): rule-based
  detection is **strong on structured/administrative/form-like text and weak on free
  conversation**. ko-pii micro-F1 = 0.660 on KDPII (conversational) but 0.790 / 0.825 on the
  form-like synthetic sets. **Honmoon's real inspection surface is structured payloads
  (JSON/form/SQL/headers), not free chat** → the form-like numbers are the realistic operating
  target; KDPII conversational is the pessimistic floor.

## 4. Target PII types (3 tiers)

ko-pii's taxonomy, re-grouped from Honmoon's policy angle (blocking value × detection difficulty).

**Tier 1 — Deterministic: checksum/structure-verifiable, near-zero false positives**
RRN (resident registration no.), FRN (foreign registration no.), business reg. no., corporate
reg. no., driver's license, passport, credit card (BIN+Luhn), email, IP, phone, account number,
vehicle plate.
→ **Top priority for `deny`.** Near-perfect achievable with regex + checksum.

**Tier 2 — Format/dictionary based: regex + keyword anchors**
postal code, URL, health-insurance/prescription and other medical IDs, employee ID, case/civil
complaint numbers, date of birth / age.
→ Needs anchor context. Variable precision.

**Tier 3 — Quasi-identifiers / context-dependent: needs NER/heuristics**
person name (PERSON), nickname, address (ADDRESS), affiliation (workplace/department/club),
education, position, nationality, religion, gender, military.
→ **The hard part.** Even ko-pii scores PERSON F1 0.135, ADDRESS 0.241. Inline rules alone
   are insufficient → NER assist layer. These default to `audit` (de-id / comparability value),
   not block.

## 5. Evaluation metrics

Adopt the ko-pii / KDPII methodology verbatim to preserve comparability.

- **Entity (span)-level Precision / Recall / F1** (+ TP/FP/FN). Not token-level.
- **Per-label F1** + **micro-averaged F1** (overall).
- Scoring match: use ko-pii's subset-substring, position-insensitive matcher; apply
  `person_min_length=3` (drop 1–2 char names) identically.
- **Latency**: mean + p99 per document (ms), throughput (docs/s, single CPU core).
- **Policy operating metrics (security-specific)**: a false positive blocks legitimate
  traffic → high usability cost. So evaluate **block mode precision-first** and **audit mode
  recall-first** separately.

## 6. Dataset construction

Two non-negotiables, or the benchmark lies: **(a) mirror the surface Honmoon actually
inspects** (wire payloads, not essays), and **(b) carry enough negatives** to measure
precision (a false positive blocks legitimate traffic).

### 6.1 Unified record schema

Every source is normalized into one JSONL schema (`datasets/pii/schema.json`). One document
per line:

```jsonc
{
  "id": "kdpii-test-00042",
  "source": "kdpii", // kdpii | ko-pii-synth | honmoon-synth | honmoon-negative
  "surface": "prose", // prose | http-json | http-form | url-query | sql | header
  "lang": "ko",
  "text": "제 주민번호는 900101-1234567 이고 ...",
  "spans": [
    { "start": 7, "end": 21, "label": "RRN", "text": "900101-1234567", "tier": 1 }
  ],
  "meta": { "split": "test", "difficulty": "hard", "domain": "chat" }
}
```

- Empty `spans` ⇒ a **negative** document (precision probe).
- `label` is always a **Honmoon canonical label** (`datasets/pii/labels.yaml`); the scorer only
  ever consumes this one schema.

### 6.2 Source roles

| source | what | role |
|--------|------|------|
| `kdpii` (official splits) | Korean conversational, real-data lineage | primary recall / context eval |
| `ko-pii-synth` (540 / 1,938) | administrative / form-like synthetic | per-label & regression |
| `honmoon-synth` | **we generate** — checksum-valid fakes in payload surfaces | Tier-1 coverage + real surface |
| `honmoon-negative` | **we generate** — PII-shaped non-PII | precision / hard negatives |

### 6.3 The two boosts that matter

**(a) Payload surfaces.** KDPII / ko-pii are prose; Honmoon inspects HTTP JSON bodies, forms,
URL queries, SQL values. Re-wrap the same PII into those surfaces so the eval reflects reality:

```text
{"surface":"http-json","text":"{\"user\":{\"rrn\":\"900101-1234567\"}}","spans":[...]}
{"surface":"sql","text":"INSERT INTO members(name,ssn) VALUES ('홍길동','900101-1234567')","spans":[...]}
```

**(b) Hard negatives.** Inject "looks like PII but isn't" so precision is measured, not assumed:
order / tracking / session IDs, **checksum-invalid** RRN & business numbers (must pass), Luhn-fail
cards, UUIDs, git SHAs, base64 tokens, dates resembling an RRN prefix.

### 6.4 Label mapping (fix first)

Honmoon owns the canonical label set; each source is absorbed via `labels.yaml`. Unmapped source
labels are scored as `O` (excluded) and documented. The KDPII column needs the real label names
from the official `test.json` (Zenodo) before it is final (see Open questions).

### 6.5 Test-set composition

Build from public sources + our generators — **do not subsample** the public sets (that breaks
comparability with ko-pii's published numbers). Use KDPII's own `valid`/`test` separation to
prevent leakage: `valid` → dev, `test` → frozen. Independent public sets are the headline
scoreboard; our generated sets are surface/precision boosters, reported separately (so we never
grade our own generator with our own detector as the headline number).

**Frozen TEST** (final numbers + CI gate; never inspected) — ≈ 8,600+ docs:

| Layer | Set | Size | Surface | Role / target |
|-------|-----|------|---------|------|
| Headline (comparable) | KDPII **full `test`** | 4,891 | prose (conversational) | direct ko-pii compare · micro-F1 **≥ 0.70** (floor) |
| Operating (real surface) | ko-pii `generated_eval` (validated) | 540 | form/admin | human-audited 98.8% · micro-F1 **≥ 0.80** |
| Surface coverage | `honmoon-synth` (generated) | ~1,200 (≈200 × 6 surfaces) | http-json/form/url/sql/header | Tier-1 per-label F1 **≥ 0.98** (reported separately) |
| Precision | `honmoon-negative` (generated) | ≥ 2,000 | all | hard negatives · FP rate; ~1:1 with Tier-1 positives |

**DEV / calibration** (the only data we inspect, for tuning regex/thresholds):
- KDPII `valid` split · ko-pii extended extras (1,398, format-only validation → noisy) · dev
  slices of `honmoon-synth` / `honmoon-negative`.

**Scoring report**: headline = KDPII-test & ko-pii-540 micro-F1 (scored with the same matcher as
ko-pii/Presidio for apples-to-apples); breakdown = per-tier / per-surface / per-label F1 + negative
FP rate.

### 6.6 Layout & privacy

```
datasets/pii/
  schema.json            # unified record JSON Schema
  labels.yaml            # canonical labels + source mapping
  raw/                   # originals — gitignored, attribution kept (CC-BY)
  build/                 # normalize_kdpii.ts · gen_synth.ts · gen_negative.ts
  eval/                  # dev.jsonl · test.jsonl (frozen build output)
  score.ts               # scorer using ko-pii's match rule
```

**No real PII is stored.** `honmoon-synth` emits format/checksum-valid but non-existent values
(Faker-style). `raw/` (KDPII etc.) is gitignored with CC-BY-4.0 attribution.

## 7. Target numbers (Functional Requirements / Acceptance Criteria)

Baseline: ko-pii (KDPII micro-F1 **0.660**, synthetic set **0.790**) — the current
Korean open-source SOTA. Honmoon aims for "ko-pii parity or better, while keeping inline speed."

- **FR1 (Tier 1 deterministic PII)**: the blocking core. On KDPII + synthetic set:
  - AC1: RRN/FRN/email/IP/phone/card **per-label F1 ≥ 0.98**, **precision ≥ 0.99**
    (ko-pii measured: RRN/EMAIL/IP/FRN ≈ 1.00, PHONE 0.992 → achievable).
- **FR2 (overall micro-F1)**: split by surface, since rule-based detection differs sharply
  between free conversation and structured payloads (ko-pii: 0.660 conversational vs 0.790/0.825
  form-like).
  - AC2a (KDPII conversational, pessimistic floor): **micro-F1 ≥ 0.70** (beats ko-pii's 0.660).
  - AC2b (form-like / payload surface — Honmoon's real surface): **micro-F1 ≥ 0.80** (ko-pii
    parity on `generated_eval` 0.790 / extended 0.825).
  - AC3 (stretch, payload surface): **micro-F1 ≥ 0.85**.
- **FR3 (Tier 3 quasi-identifiers)**: with NER assist layer enabled
  - AC4: PERSON **F1 ≥ 0.40**, ADDRESS **F1 ≥ 0.45** (vs ko-pii 0.135 / 0.241).
- **FR4 (latency, inline)**: Tier 1+2 rule layer standalone
  - AC5: mean **≤ 0.5 ms/doc**, **p99 ≤ 2 ms/doc** (single CPU core). Keep ko-pii's 0.19 ms
    at parity-or-lower in Rust.
  - AC6: keep the NER layer **off the inline path** (audit/async); even when enabled, p99 add
    ≤ 5 ms or handle via a separate queue.
- **FR5 (baseline superiority)**: same scorer, same sets
  - AC7: Honmoon ≥ ko-pii (all metrics), and ≫ Presidio (kr_adapt, KDPII F1 0.273).
- **FR6 (robustness)**: no panic on malformed/abnormal input; no FP blow-up on empty-gold
  documents (18/540 in the synthetic set).

## 8. Baseline comparators

- **ko-pii** (MIT) — primary comparator and the porting reference. Ships its own scorer
  (`ko_pii.eval`).
- **Presidio** (MIT, `kr_adapt`) — global-standard comparator. Has KR recognizers
  (KR_RRN/FRN/passport/driver-license/business-reg-no) but they are off by default and
  NER-dependent → inferior in both Korean accuracy and speed. Failure mode is **low recall, not
  low precision**: on the synthetic set precision 0.794 but recall 0.347 (KDPII F1 0.273); it
  emits **0 on many Korean categories** (AGE, POSITION, RRN, …). Speed 4.2 ms/doc (ko-pii is 22×
  faster). So Presidio loses on *coverage* and *latency*, not per-hit accuracy.
- **scrubadub** (Apache-2.0, per LICENSE) — English-centric, **no Korean support** → excluded
  from Korean evaluation; English regression reference only.

## 9. Proposed milestones

1. **M0 data & harness**: normalize the KDPII official splits + ko-pii synthetic set into the
   eval format, fix the label-mapping table, reproduce the ko-pii scorer (or an equivalent Rust
   scorer). Re-measure ko-pii / Presidio baseline numbers.
2. ✅ **M1 Tier 1 rule engine (Rust)**: deterministic PII regex + checksum. AC1 met on
   `honmoon-synth` (F1 1.000 for RRN/card/phone/email/IP); see §9.1. `pii_scan` bridge +
   `score.ts` form the measurement loop.
3. **M2 Tier 2 + CEL fact wiring**: expose `pii.*` facts to the policy engine, wire to
   `deny`/`pause`. AC2.
4. **M3 NER assist layer (optional)**: improve Tier 3. AC4. Keep it off the inline path (AC6).
5. **M4 regression gate**: pin micro-F1 / p99 regression thresholds in CI.

## 9.1 Measured results — Tier-1 M1

First end-to-end measurement of the Rust Tier-1 detector (`honmoon-core::pii`), scored with
`datasets/pii/score.ts` (entity-level, `match_forms_overlap`). Reproduce:

```sh
cargo build -p honmoon-core --example pii_scan
target/debug/examples/pii_scan < <gold>.jsonl > <pred>.jsonl   # rewrites only `spans`
bun datasets/pii/score.ts <gold>.jsonl <pred>.jsonl
```

| Set | Labels | Result |
| --- | --- | --- |
| **honmoon-synth** (valid checksums, payload surfaces) | RRN, CREDIT_CARD, PHONE, EMAIL, IP | **F1 = 1.000** each (P 1.0 / R 1.0) — **meets AC1 (≥ 0.98)** |
| **honmoon-negative** (2 000 hard negatives) | — | **3 false positives total** (all FRN-shaped bare 13-digit refs) — 1 997 / 2 000 docs clean. Precision is undefined on a negative-only set (no true positives); the metric is the raw FP count. **Supports FR6** (no FP blow-up on empty-gold docs) |
| **KDPII** (conversational) | EMAIL, IP, FRN | **F1 = 1.000** |
| **KDPII** | PHONE | F1 0.888 (R 0.80) — remaining misses are spaced / legacy formats |
| **KDPII** | RRN, CREDIT_CARD | F1 ≈ 0.10 — see caveat |

**Caveat — KDPII RRN/card values are checksum-invalid.** The KDPII synthetic corpus generates RRN
and card numbers with **random check digits** (verified: 5/6 sampled RRNs fail the mod-11 checksum,
4/4 cards fail Luhn). A precision-first checksum/Luhn detector therefore *cannot and should not*
match them, so KDPII RRN/card recall is structurally ~0. This is a property of the test data, not a
detector defect — the same labels score 1.000 on `honmoon-synth`, which uses valid checksums.
**Conclusion: measure AC1 (checksum-gated labels) on `honmoon-synth`; use KDPII for format-based
labels (email/IP/phone/FRN) and conversational recall.**

The 3 FRN false positives are the precision cost of detecting *unhyphenated* FRNs (a reviewer
request); requiring the hyphen would zero them but miss bare FRNs. Deferred labels
(ACCOUNT/passport/driver/vehicle) score 0 by design — keyword-anchored, slated for Tier-2.

## 10. Open questions

- ✅ KDPII inventoried from Zenodo `test.json` (33 labels, all mapped in `labels.yaml`).
  Remaining: confirm **ko-pii's own KDPII label mapping** matches ours so the micro-F1 numbers
  are truly apples-to-apples (ko-pii folds KDPII into its 33 categories its own way).
- Default block policy: which tiers/labels default to `deny` vs `pause` vs `audit`.
- Whether to adopt PII-Bench-style **query-aware masking** (preserve needed info) as a
  long-term goal.
- PII-Bench license (redistribution rights).

## Sources

- ko-pii: `Marker-Inc-Korea/ko-pii` `README.md`, `docs/BENCHMARK.md`, `data/` (MIT)
- KDPII: IEEE Access 2024 `10681073`, Zenodo `10968609` (CC-BY-4.0)
- Presidio: `microsoft/presidio` `docs/supported_entities.md`, `microsoft/presidio-research` (MIT)
- scrubadub: `LeapBeyond/scrubadub`, readthedocs (Apache-2.0 per LICENSE)
- PII-Bench: arXiv 2502.18545 (Fudan University)
