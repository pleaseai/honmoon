// Normalize KDPII (Zenodo 10968609) JSON into the unified eval schema.
//
//   bun datasets/pii/build/normalize_kdpii.ts <kdpii.json> <split> > out.jsonl
//   e.g. bun datasets/pii/build/normalize_kdpii.ts raw/kdpii/test.json test > eval/kdpii-test.jsonl
//
// KDPII record shape: { sent_idx, sentence, PII_set: [{ id, form, label, begin, end }], ... }
// `begin`/`end` are code-point offsets into `sentence`; for BMP Korean these equal UTF-16 units.

import type { EvalRecord, Span } from './types.ts'
import { readFileSync } from 'node:fs'
import { assertValidRecords, loadLabels, toJsonl } from './types.ts'

interface KdpiiPii { form: string, label: string, begin: number, end: number }
interface KdpiiRec { sent_idx: string, sentence: string, PII_set: KdpiiPii[] }

function main() {
  const [file, split = 'test'] = process.argv.slice(2)
  if (!file) {
    console.error('usage: bun normalize_kdpii.ts <kdpii.json> [test|valid]')
    process.exit(1)
  }
  // Reject unknown splits — silently coercing e.g. `train` to `test` would
  // contaminate the frozen test set.
  if (split !== 'test' && split !== 'valid') {
    console.error(`unsupported KDPII split: ${split} (expected "test" or "valid")`)
    process.exit(1)
  }
  const cfg = loadLabels()
  const { fromKdpii, labels } = cfg
  const recs = JSON.parse(readFileSync(file, 'utf8')) as KdpiiRec[]

  const out: EvalRecord[] = []
  let dropped = 0
  for (const [i, r] of recs.entries()) {
    const spans: Span[] = []
    for (const p of r.PII_set ?? []) {
      const canonical = fromKdpii.get(p.label)
      if (!canonical) { // unmapped → scored as O
        dropped++
        continue
      }
      const tier = labels.get(canonical)!.tier
      const text = r.sentence.slice(p.begin, p.end)
      spans.push({ start: p.begin, end: p.end, label: canonical, text, tier })
    }
    out.push({
      id: `kdpii-${split}-${String(i).padStart(5, '0')}`,
      source: 'kdpii',
      surface: 'prose',
      lang: 'ko',
      text: r.sentence,
      spans,
      meta: { split: split === 'valid' ? 'dev' : 'test', domain: 'chat' },
    })
  }
  assertValidRecords(out, cfg)
  process.stdout.write(toJsonl(out))
  console.error(`[normalize_kdpii] ${out.length} docs, ${out.reduce((a, r) => a + r.spans.length, 0)} spans, ${dropped} unmapped spans dropped`)
}

main()
