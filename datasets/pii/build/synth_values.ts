// Deterministic generators + validators for synthetic PII values.
// Values are FORMAT/CHECKSUM-valid but NON-EXISTENT (Faker-style). No real PII. See §6.6.
// All generators take a seed so datasets are reproducible.

/** mulberry32 — tiny deterministic PRNG. */
export function rng(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a |= 0
    a = (a + 0x6D2B79F5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}
const digits = (r: () => number, n: number) => Array.from({ length: n }, () => Math.floor(r() * 10)).join('')

// ── 주민등록번호 (RRN) — weight checksum ────────────────────────────────────
const RRN_W = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
export function rrnCheckDigit(first12: string): number {
  const sum = [...first12].reduce((s, d, i) => s + Number(d) * RRN_W[i], 0)
  return (11 - (sum % 11)) % 10
}
export function genRRN(r: () => number, valid = true): string {
  const yy = String(Math.floor(r() * 100)).padStart(2, '0')
  const mm = String(1 + Math.floor(r() * 12)).padStart(2, '0')
  const dd = String(1 + Math.floor(r() * 28)).padStart(2, '0')
  const s = String(1 + Math.floor(r() * 4))
  const rest = digits(r, 5)
  const first12 = `${yy}${mm}${dd}${s}${rest}`
  let c = rrnCheckDigit(first12)
  if (!valid) { // force wrong check digit
    c = (c + 1 + Math.floor(r() * 9)) % 10
  }
  return `${yy}${mm}${dd}-${s}${rest}${c}`
}
export function isValidRRN(v: string): boolean {
  const d = v.replace(/-/g, '')
  return /^\d{13}$/.test(d) && rrnCheckDigit(d.slice(0, 12)) === Number(d[12])
}

// ── 신용카드 (Luhn) ─────────────────────────────────────────────────────────
export function luhnValid(num: string): boolean {
  const d = num.replace(/\D/g, '')
  let sum = 0
  let alt = false
  for (let i = d.length - 1; i >= 0; i--) {
    let n = Number(d[i])
    if (alt) {
      n *= 2
      if (n > 9) {
        n -= 9
      }
    }
    sum += n
    alt = !alt
  }
  return d.length >= 12 && sum % 10 === 0
}
export function genCard(r: () => number, valid = true): string {
  const body = `4${digits(r, 14)}` // 15 digits, Visa-like prefix
  let check = 0
  for (let c = 0; c < 10; c++) {
    if (luhnValid(body + c)) {
      check = c
      break
    }
  }
  if (!valid) {
    check = (check + 1 + Math.floor(r() * 8)) % 10
  }
  const full = body + check
  return full.replace(/(\d{4})(?=\d)/g, '$1-')
}

// ── contact / account ───────────────────────────────────────────────────────
export const genMobile = (r: () => number) => `010-${digits(r, 4)}-${digits(r, 4)}`
export const genPhone = (r: () => number) => `0${2 + Math.floor(r() * 6)}-${digits(r, 3)}-${digits(r, 4)}`
export const genAccount = (r: () => number) => `${digits(r, 6)}-${digits(r, 2)}-${digits(r, 6)}`
const NAMES = ['minsu', 'jiwoo', 'haeun', 'noir', 'lamingo', 'serena']
const DOMAINS = ['gmail.com', 'naver.com', 'kakao.com', 'daum.net']
export function genEmail(r: () => number): string {
  const n = NAMES[Math.floor(r() * NAMES.length)] + digits(r, 3)
  return `${n}@${DOMAINS[Math.floor(r() * DOMAINS.length)]}`
}
export function genIPv4(r: () => number) {
  return Array.from({ length: 4 }, () => Math.floor(r() * 254) + 1).join('.')
}
