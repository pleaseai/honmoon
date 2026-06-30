// Shared types + label-config loader for the PII benchmark dataset pipeline.
// See docs/pii-benchmark-goals.md §6. Run with Bun (e.g. `bun datasets/pii/build/...`).

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse as parseYaml } from 'yaml'

export type Surface = 'prose' | 'http-json' | 'http-form' | 'url-query' | 'sql' | 'header'
export type Source = 'kdpii' | 'ko-pii-synth' | 'honmoon-synth' | 'honmoon-negative'
export type Tier = 1 | 2 | 3

/** One gold span. Offsets index into `text` as UTF-16 code units (JS String semantics). */
export interface Span {
  start: number
  end: number
  label: string // canonical label key
  text: string // === text.slice(start, end)
  tier: Tier
}

/** One evaluation document — mirrors datasets/pii/schema.json. */
export interface EvalRecord {
  id: string
  source: Source
  surface: Surface
  lang: 'ko' | 'en'
  text: string
  spans: Span[] // empty ⇒ negative document
  meta?: { split?: 'dev' | 'test', difficulty?: 'easy' | 'medium' | 'hard', domain?: string }
}

export interface LabelDef {
  key: string
  tier: Tier
  severity: 'high' | 'medium' | 'low'
  method: string
  defaultAction: 'deny' | 'pause' | 'audit'
  refF1: number | null
}

export interface LabelConfig {
  labels: Map<string, LabelDef>
  /** source label code → canonical key, per source. */
  fromKdpii: Map<string, string>
  fromKoPii: Map<string, string>
  fromPresidio: Map<string, string>
}

const HERE = dirname(fileURLToPath(import.meta.url))
const LABELS_YAML = join(HERE, '..', 'labels.yaml')

function asArray(v: unknown): string[] {
  if (v == null) {
    return []
  }
  if (Array.isArray(v)) {
    return v.map((item) => {
      if (typeof item !== 'string') {
        throw new TypeError(`labels.yaml mapping entries must be strings, got ${typeof item}`)
      }
      return item
    })
  }
  if (typeof v === 'string') {
    return [v]
  }
  throw new TypeError(`labels.yaml mapping value must be a string or string[], got ${typeof v}`)
}

/** Load and index labels.yaml (the single source of truth for canonical labels + mapping). */
export function loadLabels(path = LABELS_YAML): LabelConfig {
  const doc = parseYaml(readFileSync(path, 'utf8')) as {
    labels: Record<string, {
      tier: Tier
      severity: LabelDef['severity']
      method: string
      default_action: LabelDef['defaultAction']
      ref_f1: number | null
      map: { ko_pii?: unknown, presidio?: unknown, kdpii?: unknown }
    }>
  }
  const labels = new Map<string, LabelDef>()
  const fromKdpii = new Map<string, string>()
  const fromKoPii = new Map<string, string>()
  const fromPresidio = new Map<string, string>()

  for (const [key, v] of Object.entries(doc.labels)) {
    labels.set(key, {
      key,
      tier: v.tier,
      severity: v.severity,
      method: v.method,
      defaultAction: v.default_action,
      refF1: v.ref_f1,
    })
    for (const c of asArray(v.map.kdpii)) {
      fromKdpii.set(c, key)
    }
    for (const c of asArray(v.map.ko_pii)) {
      fromKoPii.set(c, key)
    }
    for (const c of asArray(v.map.presidio)) {
      fromPresidio.set(c, key)
    }
  }
  return { labels, fromKdpii, fromKoPii, fromPresidio }
}

/** Serialize records to JSONL. */
export function toJsonl(records: EvalRecord[]): string {
  return `${records.map(r => JSON.stringify(r)).join('\n')}\n`
}

/** Parse JSONL into records. */
export function fromJsonl(text: string): EvalRecord[] {
  return text.split('\n').filter(l => l.trim()).map(l => JSON.parse(l) as EvalRecord)
}

/**
 * Enforce the canonical record contract that JSON Schema cannot express
 * (cross-field `end > start`, and `label`/`tier` consistency with labels.yaml).
 * Throws on the first violation so malformed data fails fast instead of
 * silently poisoning offset-based scoring.
 */
export function assertValidRecords(records: EvalRecord[], cfg: LabelConfig): void {
  for (const r of records) {
    for (const s of r.spans) {
      if (!(s.start >= 0 && s.end > s.start)) {
        throw new Error(`${r.id}: invalid span offsets {start:${s.start}, end:${s.end}}`)
      }
      const def = cfg.labels.get(s.label)
      if (!def) {
        throw new Error(`${r.id}: unknown canonical label "${s.label}" (not in labels.yaml)`)
      }
      if (def.tier !== s.tier) {
        throw new Error(`${r.id}: tier ${s.tier} disagrees with labels.yaml (${s.label} is tier ${def.tier})`)
      }
    }
  }
}
