import { useEffect, useState } from 'react'

/**
 * Returns true once the page is scrolled past `threshold` px. Drives the top
 * nav's frosted-glass state (`.topnav.scrolled`) — transparent over the hero,
 * frosted once scrolled. Mirrors the original `scrollY > 24` toggle.
 */
export function useScrollFlag(threshold = 24): boolean {
  const [flagged, setFlagged] = useState(() => (window.scrollY || 0) > threshold)

  useEffect(() => {
    const onScroll = () => setFlagged((window.scrollY || 0) > threshold)
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [threshold])

  return flagged
}
