// CI regression gate for the Tier-1 PII detector. Scores predictions against a
// gold set and exits non-zero if a threshold is breached, so accuracy can't
// silently regress. See docs/pii-benchmark-goals.md §9.1.
//
//   bun datasets/pii/gate.ts <profile> <gold.jsonl> <pred.jsonl>
//
// profiles:
//   synth    — Tier-1 micro-F1 plus per-label F1/precision floors (AC1).
//   negative — total false-positive budget on hard negatives (FR6).
//
// Both gold sets are regenerated deterministically (seeded) from build/, so the
// gate needs no vendored corpora — KDPII (download-only) is excluded here.

import type { LabelScore } from './score.ts'
import { appendFileSync, readFileSync } from 'node:fs'
import { assertValidRecords, fromJsonl, loadLabels } from './build/types.ts'
import { prf, score } from './score.ts'

// AC1 floors: Tier-1 micro F1 ≥ 0.98, per-label F1 ≥ 0.90, AND per-label precision ≥ 0.99.
// Gating F1 alone would let a false-positive regression pass as long as recall compensates,
// so precision is checked separately.
const F1_FLOOR = 0.98
const PER_LABEL_F1_FLOOR = 0.90
const PRECISION_FLOOR = 0.99
// Labels with valid-checksum/format positives in honmoon-synth (AC1). ACCOUNT is
// deferred (keyword-anchored, Tier-2) so it is intentionally not gated.
const SYNTH_LABELS = ['RRN', 'CREDIT_CARD', 'PHONE', 'EMAIL', 'IP']
// Hard-negative FP budget (supports FR6 — no FP blow-up on empty-gold documents):
// the detector emits 3; small headroom catches a regression without flapping.
const NEGATIVE_FP_BUDGET = 5

type Profile = 'synth' | 'negative'

function summaryTable(title: string, scores: Array<[string, LabelScore]>): void {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY
  if (!summaryPath) {
    return
  }

  const lines = [
    `### ${title}`,
    '',
    '| Label | F1 | Precision | Recall | TP | FP | FN |',
    '| --- | ---: | ---: | ---: | ---: | ---: | ---: |',
    ...scores.map(([label, s]) => `| ${label} | ${s.f1.toFixed(3)} | ${s.precision.toFixed(3)} | ${s.recall.toFixed(3)} | ${s.tp} | ${s.fp} | ${s.fn} |`),
    '',
  ]
  // The summary table is auxiliary — never let a write failure fail the gate itself.
  try {
    appendFileSync(summaryPath, `${lines.join('\n')}\n`)
  }
  catch (err) {
    console.warn(`⚠️ Failed to write to GITHUB_STEP_SUMMARY: ${err}`)
  }
}

function fail(msg: string): never {
  console.error(`❌ PII gate FAILED: ${msg}`)
  process.exit(1)
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
    const offenders: string[] = []
    const scoredLabels: Array<[string, LabelScore]> = []
    for (const label of SYNTH_LABELS) {
      const s = report.perLabel.get(label) ?? { tp: 0, fp: 0, fn: 0, precision: 0, recall: 0, f1: 0 }
      scoredLabels.push([label, s])
      console.log(`  ${label.padEnd(14)} F1=${s.f1.toFixed(3)} P=${s.precision.toFixed(3)}`)
      if (s.f1 < PER_LABEL_F1_FLOOR) {
        offenders.push(`${label} F1 ${s.f1.toFixed(3)}<${PER_LABEL_F1_FLOOR}`)
      }
      if (s.precision < PRECISION_FLOOR) {
        offenders.push(`${label} P ${s.precision.toFixed(3)}<${PRECISION_FLOOR}`)
      }
    }
    // Matching is label-scoped (score.ts groups spans by label before matching),
    // so the Tier-1 micro score equals the aggregate of the per-label counts
    // already in `report` — no need to re-score a filtered copy of the datasets.
    let tp = 0
    let fp = 0
    let fn = 0
    for (const label of SYNTH_LABELS) {
      const s = report.perLabel.get(label)
      tp += s?.tp ?? 0
      fp += s?.fp ?? 0
      fn += s?.fn ?? 0
    }
    const tier1 = prf(tp, fp, fn)
    scoredLabels.push(['Tier-1 micro', tier1])
    console.log(`  ${'Tier-1 micro'.padEnd(14)} F1=${tier1.f1.toFixed(3)} P=${tier1.precision.toFixed(3)}`)
    if (tier1.f1 < F1_FLOOR) {
      offenders.push(`Tier-1 micro F1 ${tier1.f1.toFixed(3)}<${F1_FLOOR}`)
    }
    summaryTable('PII Tier-1 benchmark', scoredLabels)
    if (offenders.length > 0) {
      fail(`AC1 floor breached: ${offenders.join(', ')}`)
    }
    console.log(`✅ PII gate (synth): Tier-1 micro F1 ≥ ${F1_FLOOR}; all ${SYNTH_LABELS.length} labels F1 ≥ ${PER_LABEL_F1_FLOOR}, P ≥ ${PRECISION_FLOOR}`)
  }
  else if (profile === ('negative' satisfies Profile)) {
    const fp = report.micro.fp
    console.log(`  false positives: ${fp} (budget ${NEGATIVE_FP_BUDGET})`)
    summaryTable('PII hard-negative benchmark', [['All hard negatives', report.micro]])
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
