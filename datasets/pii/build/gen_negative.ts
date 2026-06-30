// Generate HARD NEGATIVE records: "looks like PII but isn't" — must produce zero detections.
// This is the precision scoreboard (a false positive blocks legitimate traffic). See §6.3(b).
//
//   bun datasets/pii/build/gen_negative.ts [perKind] [seed] > eval/honmoon-negative.jsonl

import type { EvalRecord, Surface } from './types.ts'
import { genCard, genRRN, rng } from './synth_values.ts'
import { toJsonl } from './types.ts'

const SURFACES: Surface[] = ['prose', 'http-json', 'http-form', 'url-query', 'sql', 'header']
const hex = (r: () => number, n: number) => Array.from({ length: n }, () => Math.floor(r() * 16).toString(16)).join('')
const dig = (r: () => number, n: number) => Array.from({ length: n }, () => Math.floor(r() * 10)).join('')

interface Kind { name: string, gen: (r: () => number) => string }
const KINDS: Kind[] = [
  { name: 'invalid-rrn', gen: r => genRRN(r, false) }, // wrong checksum → not an RRN
  { name: 'luhn-fail-card', gen: r => genCard(r, false) }, // wrong Luhn → not a card
  { name: 'order-no', gen: r => `ORD-${dig(r, 10)}` },
  { name: 'tracking-no', gen: r => dig(r, 13) },
  { name: 'session-id', gen: r => hex(r, 32) },
  { name: 'uuid', gen: r => `${hex(r, 8)}-${hex(r, 4)}-${hex(r, 4)}-${hex(r, 4)}-${hex(r, 12)}` },
  { name: 'git-sha', gen: r => hex(r, 40) },
  { name: 'rrn-like-date', gen: r => `${dig(r, 6)}-0000000` }, // date-shaped prefix, no valid tail
]

function wrap(surface: Surface, value: string): string {
  switch (surface) {
    case 'prose': return `주문 처리 번호는 ${value} 입니다.`
    case 'http-json': return `{"ref":"${value}","ok":true}`
    case 'http-form': return `ref=${value}&ok=true`
    case 'url-query': return `/track?ref=${value}`
    case 'sql': return `SELECT * FROM orders WHERE ref = '${value}';`
    case 'header': return `X-Request-Id: ${value}`
  }
}

function main() {
  const per = Number(process.argv[2] ?? 250) // 250 × 8 kinds = 2,000 docs cycled over surfaces
  const seed = Number(process.argv[3] ?? 7)
  const r = rng(seed)
  const out: EvalRecord[] = []
  let n = 0
  for (const k of KINDS) {
    for (let i = 0; i < per; i++) {
      const surface = SURFACES[i % SURFACES.length]
      out.push({
        id: `honmoon-negative-${String(n++).padStart(5, '0')}`,
        source: 'honmoon-negative',
        surface,
        lang: 'ko',
        text: wrap(surface, k.gen(r)),
        spans: [], // negative: no PII
        meta: { split: i % 5 === 0 ? 'dev' : 'test', difficulty: 'hard', domain: k.name },
      })
    }
  }
  process.stdout.write(toJsonl(out))
  console.error(`[gen_negative] ${out.length} negative docs across ${KINDS.length} hard-negative kinds`)
}

main()
