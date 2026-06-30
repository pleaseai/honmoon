// CI regression gate for the Tier-1 PII detector. Scores predictions against a
// gold set and exits non-zero if a threshold is breached, so accuracy can't
// silently regress. See docs/pii-benchmark-goals.md §9.1.
//
//   bun datasets/pii/gate.ts <profile> <gold.jsonl> <pred.jsonl>
//
// profiles:
//   synth    — per-label F1 floor for checksum/format labels (AC1).
//   negative — total false-positive budget on hard negatives (AC3).
//
// Both gold sets are regenerated deterministically (seeded) from build/, so the
// gate needs no vendored corpora — KDPII (download-only) is excluded here.

import type { LabelScore } from './score.ts'
import { readFileSync } from 'node:fs'
import { assertValidRecords, fromJsonl, loadLabels } from './build/types.ts'
import { score } from './score.ts'

const F1_FLOOR = 0.98
// Labels with valid-checksum/format positives in honmoon-synth (AC1). ACCOUNT is
// deferred (keyword-anchored, Tier-2) so it is intentionally not gated.
const SYNTH_LABELS = ['RRN', 'CREDIT_CARD', 'PHONE', 'EMAIL', 'IP']
// Hard-negative FP budget: current detector emits 3; small headroom catches a
// regression without flapping on a single new edge case.
const NEGATIVE_FP_BUDGET = 5

type Profile = 'synth' | 'negative'

function fail(msg: string): never {
  console.error(`❌ PII gate FAILED: ${msg}`)
  process.exit(1)
}

function f1(s: LabelScore | undefined): number {
  return s ? s.f1 : 0
}

function main(): void {
  const [profile, goldPath, predPath] = process.argv.slice(2)
  if (!profile || !goldPath || !predPath) {
    fail('usage: bun gate.ts <synth|negative> <gold.jsonl> <pred.jsonl>')
  }

  const cfg = loadLabels()
  const gold = fromJsonl(readFileSync(goldPath, 'utf8'))
  const pred = fromJsonl(readFileSync(predPath, 'utf8'))
  assertValidRecords(gold, cfg)
  assertValidRecords(pred, cfg)
  const report = score(gold, pred)

  if (profile === ('synth' satisfies Profile)) {
    const offenders = SYNTH_LABELS
      .map(label => ({ label, s: f1(report.perLabel.get(label)) }))
      .filter(({ s }) => s < F1_FLOOR)
    for (const label of SYNTH_LABELS) {
      console.log(`  ${label.padEnd(14)} F1=${f1(report.perLabel.get(label)).toFixed(3)}`)
    }
    if (offenders.length > 0) {
      const detail = offenders.map(({ label, s }) => `${label} ${s.toFixed(3)}`).join(', ')
      fail(`F1 below ${F1_FLOOR} for: ${detail}`)
    }
    console.log(`✅ PII gate (synth): all ${SYNTH_LABELS.length} labels F1 ≥ ${F1_FLOOR}`)
  }
  else if (profile === ('negative' satisfies Profile)) {
    const fp = report.micro.fp
    console.log(`  false positives: ${fp} (budget ${NEGATIVE_FP_BUDGET})`)
    if (fp > NEGATIVE_FP_BUDGET) {
      fail(`${fp} false positives on hard negatives exceeds budget ${NEGATIVE_FP_BUDGET}`)
    }
    console.log(`✅ PII gate (negative): ${fp} FP ≤ budget ${NEGATIVE_FP_BUDGET}`)
  }
  else {
    fail(`unknown profile '${profile}' (expected 'synth' or 'negative')`)
  }
}

main()
