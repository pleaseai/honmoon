import type { ReactNode } from 'react'

/** Double-bezel surface: translucent outer shell around a concentric glass core. */
export function Panel({
  children,
  className = '',
  glassClassName = '',
}: {
  children: ReactNode
  className?: string
  glassClassName?: string
}) {
  return (
    <div className={`bezel ${className}`}>
      <div className={`glass ${glassClassName}`}>{children}</div>
    </div>
  )
}

/**
 * Page title block: eyebrow, display title, one-line description, optional
 * mono meta. Its bottom margin equals the Overview hero's gap to its first
 * card (hero `pb-9` plus the grid's `mt-3.5`), so every route lands its
 * first panel at the same offset below the app header.
 */
export function PageHead({
  eyebrow,
  title,
  description,
  meta,
}: {
  eyebrow: string
  title: string
  description: string
  meta?: ReactNode
}) {
  return (
    <header className="mb-[50px] flex flex-wrap items-end gap-x-6 gap-y-3">
      <div>
        <p className="eyebrow mb-2">{eyebrow}</p>
        <h1 className="font-display text-[30px] leading-[1.15] font-semibold tracking-[-0.025em]">
          {title}
        </h1>
        <p className="mt-2 text-[12.5px] leading-relaxed text-muted">{description}</p>
      </div>
      {meta && <span className="meta-mono ml-auto">{meta}</span>}
    </header>
  )
}

/** Section title inside a panel: title left, mono meta right. */
export function SectionHead({ title, meta }: { title: string, meta?: ReactNode }) {
  return (
    <header className="flex items-center px-5 pt-[18px] pb-3">
      <h2 className="text-sm font-semibold">{title}</h2>
      {meta && <span className="meta-mono ml-auto text-[9.5px]">{meta}</span>}
    </header>
  )
}

/** A fetch or action failure. Always distinct from an empty, healthy surface. */
export function ErrorNote({ message, className = 'mb-4' }: { message: string, className?: string }) {
  return (
    <p
      role="alert"
      className={`rounded-[14px] bg-deny-soft px-4 py-3 text-xs text-deny-ink shadow-[inset_0_0_0_1px_var(--deny-line)] ${className}`}
    >
      {message}
    </p>
  )
}

/** Centered state inside a panel: loading, empty, or unavailable. */
export function PanelState({
  glyph,
  children,
  tone = 'neutral',
}: {
  glyph: string
  children: ReactNode
  tone?: 'neutral' | 'error'
}) {
  const mark = tone === 'error'
    ? 'bg-deny-soft text-deny-ink'
    : 'bg-accent-soft text-accent-ink'
  return (
    <div className="grid min-h-[260px] place-items-center px-6 py-10 text-center text-muted">
      <div>
        <div
          aria-hidden="true"
          className={`mx-auto mb-3.5 grid size-[54px] place-items-center rounded-[18px] font-mono text-lg font-semibold ${mark}`}
        >
          {glyph}
        </div>
        <p className="text-xs">{children}</p>
      </div>
    </div>
  )
}
