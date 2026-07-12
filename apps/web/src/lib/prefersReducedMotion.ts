// Single source for the reduced-motion check used by the animation hooks, so the
// media query lives in one place.
export function prefersReducedMotion(): boolean {
  return matchMedia('(prefers-reduced-motion: reduce)').matches
}
