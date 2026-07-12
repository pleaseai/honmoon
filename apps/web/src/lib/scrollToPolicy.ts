/**
 * Shared smooth-scroll-to-policy handler. Used by both the top-nav "Get started"
 * button and the hero "See the policy engine" button, so the behaviour lives in
 * one place (matching the original design's single `goPolicy` handler).
 */
export function scrollToPolicy() {
  const el = document.getElementById('policy')
  if (!el) { return }
  const top = el.getBoundingClientRect().top + window.scrollY - 60
  window.scrollTo({ top, behavior: 'smooth' })
}
