// Entity-level PII scorer — mirrors ko-pii's `match_forms_overlap`:
// substring set matching, position-insensitive, per label, with person_min_length=3.
// See docs/pii-benchmark-goals.md §5.
//
//   bun datasets/pii/score.ts <gold.jsonl> <pred.jsonl>
//
// gold/pred are JSONL of EvalRecord (datasets/pii/schema.json); matched by `id`.

import type { EvalRecord, Span } from './build/types.ts'
import { readFileSync } from 'node:fs'
import { assertValidRecords, fromJsonl, loadLabels } from './build/types.ts'

const PERSON_MIN_LENGTH = 3

export interface LabelScore { tp: number, fp: number, fn: number, precision: number, recall: number, f1: number }
export interface ScoreReport { perLabel: Map<string, LabelScore>, micro: LabelScore }

function keep(s: Span): boolean {
  if (s.label === 'PERSON' && [...s.text].length < PERSON_MIN_LENGTH) {
    return false
  }
  return true
}

/** Overlap = one form is a substring of the other (case-insensitive). Position-insensitive. */
function overlaps(a: string, b: string): boolean {
  const x = a.trim().toLowerCase()
  const y = b.trim().toLowerCase()
  if (!x || !y) {
    return false
  }
  return x.includes(y) || y.includes(x)
}

/** Greedy bag match within one label group; returns TP count. */
function matchGroup(gold: string[], pred: string[]): number {
  const usedGold = new Set<number>()
  let tp = 0
  for (const p of pred) {
    for (let i = 0; i < gold.length; i++) {
      if (usedGold.has(i)) {
        continue
      }
      if (overlaps(p, gold[i])) {
        usedGold.add(i)
        tp++
        break
      }
    }
  }
  return tp
}

function prf(tp: number, fp: number, fn: number): LabelScore {
  const precision = tp + fp ? tp / (tp + fp) : 0
  const recall = tp + fn ? tp / (tp + fn) : 0
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0
  return { tp, fp, fn, precision, recall, f1 }
}

export function score(gold: EvalRecord[], pred: EvalRecord[]): ScoreReport {
  // Build id-keyed maps that fail loud on duplicates — a duplicate id would
  // otherwise be silently dropped and let a malformed file score better than it should.
  const goldIds = new Set<string>()
  for (const r of gold) {
    if (goldIds.has(r.id)) {
      throw new Error(`duplicate gold id: ${r.id}`)
    }
    goldIds.add(r.id)
  }
  const predById = new Map<string, EvalRecord>()
  for (const r of pred) {
    if (predById.has(r.id)) {
      throw new Error(`duplicate prediction id: ${r.id}`)
    }
    predById.set(r.id, r)
  }

  const agg = new Map<string, { tp: number, fp: number, fn: number }>()
  const bump = (label: string, k: 'tp' | 'fp' | 'fn', n: number) => {
    const a = agg.get(label) ?? { tp: 0, fp: 0, fn: 0 }
    a[k] += n
    agg.set(label, a)
  }

  for (const g of gold) {
    const p = predById.get(g.id)
    const goldSpans = g.spans.filter(keep)
    const predSpans = (p?.spans ?? []).filter(keep)
    const byLabel = new Set([...goldSpans, ...predSpans].map(s => s.label))
    for (const label of byLabel) {
      const gForms = goldSpans.filter(s => s.label === label).map(s => s.text)
      const pForms = predSpans.filter(s => s.label === label).map(s => s.text)
      const tp = matchGroup(gForms, pForms)
      bump(label, 'tp', tp)
      bump(label, 'fp', pForms.length - tp)
      bump(label, 'fn', gForms.length - tp)
    }
  }

  // Prediction records with no matching gold id are pure false positives —
  // counting them prevents precision from being inflated by over-detection
  // outside the eval set.
  for (const p of pred) {
    if (goldIds.has(p.id)) {
      continue
    }
    for (const s of p.spans.filter(keep)) {
      bump(s.label, 'fp', 1)
    }
  }

  const perLabel = new Map<string, LabelScore>()
  let TP = 0
  let FP = 0
  let FN = 0
  for (const [label, a] of agg) {
    perLabel.set(label, prf(a.tp, a.fp, a.fn))
    TP += a.tp
    FP += a.fp
    FN += a.fn
  }
  return { perLabel, micro: prf(TP, FP, FN) }
}

function main() {
  const [goldPath, predPath] = process.argv.slice(2)
  if (!goldPath || !predPath) {
    console.error('usage: bun score.ts <gold.jsonl> <pred.jsonl>')
    process.exit(1)
  }
  const cfg = loadLabels()
  const gold = fromJsonl(readFileSync(goldPath, 'utf8'))
  const pred = fromJsonl(readFileSync(predPath, 'utf8'))
  assertValidRecords(gold, cfg)
  assertValidRecords(pred, cfg)
  const rep = score(gold, pred)
  const rows = [...rep.perLabel.entries()].sort((a, b) => b[1].f1 - a[1].f1)
  console.log('label\t\tF1\tP\tR\tTP\tFP\tFN')
  for (const [label, s] of rows) {
    console.log(`${label.padEnd(16)}\t${s.f1.toFixed(3)}\t${s.precision.toFixed(3)}\t${s.recall.toFixed(3)}\t${s.tp}\t${s.fp}\t${s.fn}`)
  }
  const m = rep.micro
  console.log(`\nMICRO\t\t${m.f1.toFixed(3)}\t${m.precision.toFixed(3)}\t${m.recall.toFixed(3)}\t${m.tp}\t${m.fp}\t${m.fn}`)
}

if (import.meta.main) {
  main()
}
