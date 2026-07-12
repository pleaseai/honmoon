import { useEffect } from 'react'
import { prefersReducedMotion } from '../lib/prefersReducedMotion'

/**
 * Landing-section fade-up reveal. Observes every `.lp` section and adds `.in`
 * on first intersection so its content rises into view.
 *
 * The `.lp` hidden-initial state is gated by the `od-js` class on <html>, which
 * index.html sets **synchronously before first paint** to avoid a
 * visible→hidden→fade flash (FOUC). This hook only observes and reveals.
 *
 * reduced-motion (branch owned here): index.html does not set `od-js`, so
 * sections are visible by default; this hook skips observation entirely and
 * leaves them static.
 */
export function useReveal(rootRef: React.RefObject<HTMLElement | null>) {
  useEffect(() => {
    const root = rootRef.current
    if (!root) { return }
    const reduced = prefersReducedMotion()
    const secs = root.querySelectorAll<HTMLElement>('.lp')
    if (reduced || !('IntersectionObserver' in window) || !secs.length) { return }

    const io = new IntersectionObserver((ents) => {
      for (const e of ents) {
        if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target) }
      }
    }, { threshold: 0.14, rootMargin: '0px 0px -8% 0px' })
    secs.forEach(s => io.observe(s))

    return () => io.disconnect()
  }, [rootRef])
}
