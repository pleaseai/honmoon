import { useEffect } from 'react'
import { prefersReducedMotion } from '../lib/prefersReducedMotion'

/**
 * Barrier gate-scene scroll scrub. Updates each `.g-row`'s `--p` (0→1) as it
 * enters the viewport so its token travels from start to its verdict position.
 * Ported from the original's scroll-scrub IIFE.
 *
 * reduced-motion (branch owned here, not globally): pin every row to `--p:1`
 * (final state) and register no scroll listener.
 */
export function useGateScene(sceneRef: React.RefObject<HTMLElement | null>) {
  useEffect(() => {
    const scene = sceneRef.current
    if (!scene) { return }
    const rows = Array.prototype.slice.call(
      scene.querySelectorAll('.g-row'),
    ) as HTMLElement[]
    const reduced = prefersReducedMotion()
    if (reduced) {
      rows.forEach(r => r.style.setProperty('--p', '1'))
      return
    }

    let ticking = false
    function update() {
      ticking = false
      const vh = innerHeight
      for (const r of rows) {
        const rect = r.getBoundingClientRect()
        /* 행 상단이 뷰포트 하단쯤(88%)에 도달하면 재생, 위로 벗어나면 역재생 */
        const on = rect.top < vh * 0.88
        r.style.setProperty('--p', on ? '1' : '0')
      }
    }
    function onScroll() {
      if (!ticking) { ticking = true; requestAnimationFrame(update) }
    }
    window.addEventListener('scroll', onScroll, { passive: true })
    window.addEventListener('resize', onScroll, { passive: true })
    update()
    /* 첫 계산 이후 트랜지션 활성화 — 로드 시 튐 방지 */
    const readyId = requestAnimationFrame(() => scene.classList.add('ready'))

    return () => {
      window.removeEventListener('scroll', onScroll)
      window.removeEventListener('resize', onScroll)
      cancelAnimationFrame(readyId)
    }
  }, [sceneRef])
}
