// Generate synthetic POSITIVE records: checksum/format-valid fake PII embedded across the wire
// surfaces Honmoon actually inspects. Reproducible (seeded). See docs/pii-benchmark-goals.md §6.3.
//
//   bun datasets/pii/build/gen_synth.ts [perLabelPerSurface] [seed] > eval/honmoon-synth.jsonl
//
// TODO: extend to remaining Tier-1/2 labels (FRN, passport, driver license, business reg no, …).

import type { EvalRecord, Span, Surface } from './types.ts'
import { genAccount, genCard, genEmail, genIPv4, genMobile, genRRN, rng } from './synth_values.ts'
import { toJsonl } from './types.ts'

const SURFACES: Surface[] = ['prose', 'http-json', 'http-form', 'url-query', 'sql', 'header']

interface Gen { label: string, tier: 1 | 2, ko: string, field: string, gen: (r: () => number) => string }
const GENS: Gen[] = [
  { label: 'RRN', tier: 1, ko: '주민등록번호', field: 'rrn', gen: r => genRRN(r, true) },
  { label: 'CREDIT_CARD', tier: 1, ko: '카드번호', field: 'card_no', gen: r => genCard(r, true) },
  { label: 'PHONE', tier: 1, ko: '전화번호', field: 'phone', gen: genMobile },
  { label: 'EMAIL', tier: 1, ko: '이메일', field: 'email', gen: genEmail },
  { label: 'ACCOUNT', tier: 1, ko: '계좌번호', field: 'account_no', gen: genAccount },
  { label: 'IP', tier: 1, ko: 'IP 주소', field: 'ip', gen: genIPv4 },
]

/** Embed `value` into `surface`, returning the text and the value's offset. */
function wrap(surface: Surface, ko: string, field: string, value: string): { text: string, start: number } {
  const bySurface: Record<Surface, string> = {
    'prose': `제 ${ko}는 ${value} 입니다.`,
    'http-json': `{"user":{"${field}":"${value}"}}`,
    'http-form': `${field}=${value}&submitted=true`,
    'url-query': `/api/v1/submit?${field}=${value}&lang=ko`,
    'sql': `INSERT INTO users(${field}) VALUES ('${value}');`,
    'header': `X-${field}: ${value}`,
  }
  const text = bySurface[surface]
  return { text, start: text.indexOf(value) }
}

function main() {
  const per = Number(process.argv[2] ?? 35) // 35 × 6 surfaces × 6 labels ≈ 1,260 docs
  const seed = Number(process.argv[3] ?? 42)
  const r = rng(seed)
  const out: EvalRecord[] = []
  let n = 0
  for (const g of GENS) {
    for (const surface of SURFACES) {
      for (let i = 0; i < per; i++) {
        const value = g.gen(r)
        const { text, start } = wrap(surface, g.ko, g.field, value)
        const span: Span = { start, end: start + value.length, label: g.label, text: value, tier: g.tier }
        out.push({
          id: `honmoon-synth-${String(n++).padStart(5, '0')}`,
          source: 'honmoon-synth',
          surface,
          lang: 'ko',
          text,
          spans: [span],
          meta: { split: i % 5 === 0 ? 'dev' : 'test', domain: 'api-body' },
        })
      }
    }
  }
  process.stdout.write(toJsonl(out))
  console.error(`[gen_synth] ${out.length} positive docs across ${GENS.length} labels × ${SURFACES.length} surfaces`)
}

main()
