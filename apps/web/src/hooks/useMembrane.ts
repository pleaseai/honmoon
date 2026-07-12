import { useEffect } from 'react'
import { prefersReducedMotion } from '../lib/prefersReducedMotion'

/**
 * Full-viewport fixed membrane background (`#gate3d`).
 *
 * Ported from the original single-file design's inline canvas IIFE
 * (index-v7-inspector.html) into a React effect. Visual behaviour is kept
 * identical; only the lifecycle is React-native (rAF + listeners are torn
 * down on unmount). The original's console-synced `emitHero` / hero-particle
 * path and `window.__honmoonGate` handle are inactive in this design (nothing
 * calls them) and are intentionally omitted so the strict tsconfig
 * (noUnusedLocals) stays green.
 *
 * reduced-motion: draws one static frame, then redraws on scroll so the fixed
 * background still tracks the page — matching the original, not a hard freeze.
 */
export function useMembrane(canvasRef: React.RefObject<HTMLCanvasElement | null>) {
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) { return }
    const ctx = canvas.getContext('2d')
    if (!ctx) { return }
    const reduced = prefersReducedMotion()

    const C = {
      star: (a: number) => `rgba(196, 208, 228, ${a})`,
      raw: (a: number) => `rgba(150, 158, 178, ${a})`,
      cyan: (a: number) => `rgba(96, 226, 202, ${a})`,
      cyanHi: (a: number) => `rgba(200, 248, 238, ${a})`,
      warn: (a: number) => `rgba(255, 190, 105, ${a})`,
      deny: (a: number) => `rgba(255, 138, 118, ${a})`,
      mask: (a: number) => `rgba(206, 176, 255, ${a})`,
    }

    let W = 0; let H = 0; let cx = 0; let cy = 0
    const CAM = { z: -760, f: 640 }
    const TH = 0.62; const COS = Math.cos(TH); const SIN = Math.sin(TH) /* 카메라 요(yaw) */
    const Z_NEAR = -640; const Z_FAR = 840
    const TG = (0 - Z_NEAR) / (Z_FAR - Z_NEAR) /* 막(z=0) 통과 시점 */
    let PX = 240; let PY = 348 /* 문의 반너비/반높이 */
    const GRID = 62

    let stars: any[] = []; let nebula: any[] = []; let ambient: any[] = []; const ripples: any[] = []

    function resize() {
      const dpr = Math.min(devicePixelRatio || 1, 2)
      const rect = canvas!.getBoundingClientRect()
      W = rect.width; H = rect.height
      canvas!.width = W * dpr; canvas!.height = H * dpr
      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0)
      cx = W * (W > 920 ? 0.66 : 0.5)
      cy = H * (W > 920 ? 0.48 : 0.31)
      PX = W > 920 ? 240 : 180
      PY = W > 920 ? 348 : 275
      seedStars()
      seedNebula()
    }

    /* 카메라 워크 — draw()가 매 프레임 갱신. 기본 요(TH)에 동적 요·피치를 합성 */
    let camZ = CAM.z; let camX = 0; let camY = 0
    let yawO = 0; let pitchO = 0
    let cosY = COS; let sinY = SIN; let cp_ = 1; let sp_ = 0
    let mx = 0; let my = 0

    function onPointerMove(e: PointerEvent) {
      mx = (e.clientX / innerWidth) * 2 - 1
      my = (e.clientY / innerHeight) * 2 - 1
    }

    function proj(x: number, y: number, z: number) {
      const xr = x * cosY + z * sinY
      let zr = -x * sinY + z * cosY
      const yr = y * cp_ - zr * sp_
      zr = y * sp_ + zr * cp_
      const s = CAM.f / (zr - camZ)
      return { x: cx + camX + xr * s, y: cy + camY + yr * s, s }
    }

    function seedStars() {
      stars = []
      const n = Math.floor((W * H) / 9000)
      for (let i = 0; i < n; i++) {
        stars.push({ x: Math.random() * W, y: Math.random() * H, r: Math.random() * 1.2 + 0.3, base: Math.random() * 0.34 + 0.08, sp: Math.random() * 0.5 + 0.15, ph: Math.random() * Math.PI * 2, glow: Math.random() < 0.22, tint: Math.random() < 0.16, dx: (Math.random() - 0.5) * 0.06 })
      }
    }

    /* 은하 가스 — 크고 느리게 흐르는 글로우 구름 */
    function seedNebula() {
      nebula = []
      const cols = [C.cyan, C.mask, C.star]
      for (let i = 0; i < 6; i++) {
        nebula.push({
          x: Math.random() * W,
          y: Math.random() * H,
          r: 180 + Math.random() * (Math.min(W, H) * 0.45),
          col: cols[i % cols.length],
          a: 0.035 + Math.random() * 0.035,
          dx: (Math.random() - 0.5) * 0.05,
          dy: (Math.random() - 0.5) * 0.03,
          sp: 0.1 + Math.random() * 0.15,
          ph: Math.random() * Math.PI * 2,
        })
      }
    }

    const ease = (t: number) => t * t * (3 - 2 * t)
    const lerp = (a: number, b: number, t: number) => a + (b - a) * t

    /* 경로 — 막 위 임의 지점(hx,hy)을 향해 산개 상태에서 수렴, 통과 후 드리프트 */
    function makePath() {
      const hx = (Math.random() * 2 - 1) * PX * 0.86
      const hy = (Math.random() * 2 - 1) * PY * 0.82
      return {
        hx,
        hy,
        dx0: (Math.random() - 0.5) * 240,
        dy0: (Math.random() - 0.5) * 170,
        ex: (Math.random() - 0.5) * 90,
        ey: (Math.random() - 0.5) * 70,
      }
    }
    function posAt(p: any, t: number) {
      const z = lerp(Z_NEAR, Z_FAR, t)
      let x, y
      if (t < TG) {
        const k = ease(t / TG)
        x = p.path.hx + p.path.dx0 * (1 - k)
        y = p.path.hy + p.path.dy0 * (1 - k)
      }
      else {
        const k = (t - TG) / (1 - TG)
        x = p.path.hx + p.path.ex * k
        y = p.path.hy + p.path.ey * k
      }
      return { x, y, z }
    }

    function spawnAmbient(warm: boolean) {
      const roll = Math.random()
      const fate = roll < 0.66 ? 'pass' : (roll < 0.84 ? 'bounce' : 'dissolve')
      /* 접근하는 별똥별 일부에 이질적인 색 — 위험/이상 요청처럼 보이는 자주·금·적·청 */
      const anom = [C.mask, C.warn, C.deny, C.cyan]
      const tint = Math.random() < 0.3 ? anom[(Math.random() * anom.length) | 0] : null
      return {
        t: warm ? Math.random() : 0,
        speed: 0.0010 + Math.random() * 0.0009,
        path: makePath(),
        r: 1.2 + Math.random() * 1.0,
        tint,
        fate,
        phase: 'fly',
        hit: false,
        crossed: false,
        alpha: 1,
        b: 0,
        bang: Math.random() * Math.PI * 2,
      }
    }
    function seedAmbient() {
      ambient = []
      for (let i = 0; i < 52; i++) { ambient.push(spawnAmbient(true)) }
    }

    function addRipple(x: number, y: number, col: any, big: boolean) {
      ripples.push({ x, y, t: 0, col, big: !!big })
    }

    /* 벽에 맞고 튕겨나가는 궤적 — 접점에서 옆으로 미끄러지며 카메라 쪽으로 */
    function bouncePos(p: any, b: number) {
      return {
        x: p.path.hx + Math.cos(p.bang) * b * 180,
        y: p.path.hy + Math.sin(p.bang) * b * 130,
        z: -b * 380,
      }
    }

    function drawParticle(p: any, tm: number) {
      const t = Math.max(0, Math.min(1, p.t))
      let pos, tail
      if (p.phase === 'bounce') {
        pos = bouncePos(p, p.b)
        tail = bouncePos(p, Math.max(0, p.b - 0.09))
      }
      else if (p.phase === 'dissolve') {
        pos = { x: p.path.hx, y: p.path.hy, z: 0 }
        tail = pos
      }
      else {
        pos = posAt(p, t)
        tail = posAt(p, Math.max(0, t - 0.035))
      }
      const pr = proj(pos.x, pos.y, pos.z)
      if (pr.s > 6 || pr.s < 0) { return } /* 카메라 초근접/후방 — 과확대 방지 */
      const passed = t >= TG

      let col, alpha
      if (p.phase === 'bounce') {
        col = C.deny; alpha = p.alpha * 0.85
      }
      else if (p.phase === 'dissolve') {
        col = C.star; alpha = p.alpha * 0.7
      }
      else {
        col = p.tint || (passed ? C.cyan : C.raw)
        alpha = p.alpha * (passed ? 0.85 : (p.tint ? 0.82 : 0.55))
      }
      if (alpha <= 0) { return }
      let rad = p.r * pr.s * 1.15
      if (p.phase === 'dissolve') { rad *= 1 + (1 - p.alpha) * 1.6 }

      void tm
      if (tail !== pos) {
        const pb = proj(tail.x, tail.y, tail.z)
        const g = ctx!.createLinearGradient(pb.x, pb.y, pr.x, pr.y)
        g.addColorStop(0, col(0))
        g.addColorStop(1, col(alpha * 0.7))
        ctx!.strokeStyle = g; ctx!.lineWidth = Math.max(0.6, rad * 0.7)
        ctx!.beginPath(); ctx!.moveTo(pb.x, pb.y); ctx!.lineTo(pr.x, pr.y); ctx!.stroke()
      }

      ctx!.fillStyle = col(alpha)
      ctx!.beginPath(); ctx!.arc(pr.x, pr.y, Math.max(0.5, rad * 0.6), 0, 7); ctx!.fill()
    }

    /* 결계 멤브레인 — 격자 막 + 스캔 컬럼 + 파문 */
    function drawMembrane() {
      const c1 = proj(-PX, -PY, 0); const c2 = proj(PX, -PY, 0)
      const c3 = proj(PX, PY, 0); const c4 = proj(-PX, PY, 0)

      /* 문지방 아래 바닥 빛 — 문이 바닥에 '서 있다' */
      const fb = proj(0, PY, 0)
      ctx!.save()
      ctx!.translate(fb.x, fb.y + 6)
      ctx!.scale(1, 0.22)
      const floorG = ctx!.createRadialGradient(0, 0, 0, 0, 0, 190 * fb.s)
      floorG.addColorStop(0, C.cyan(0.16))
      floorG.addColorStop(1, C.cyan(0))
      ctx!.fillStyle = floorG
      ctx!.beginPath(); ctx!.arc(0, 0, 190 * fb.s, 0, 7); ctx!.fill()
      ctx!.restore()

      /* 막의 은은한 면 */
      ctx!.fillStyle = C.cyan(0.035)
      ctx!.beginPath()
      ctx!.moveTo(c1.x, c1.y); ctx!.lineTo(c2.x, c2.y)
      ctx!.lineTo(c3.x, c3.y); ctx!.lineTo(c4.x, c4.y)
      ctx!.closePath(); ctx!.fill()

      /* 격자 */
      ctx!.strokeStyle = C.cyan(0.13); ctx!.lineWidth = 1
      for (let x = -PX; x <= PX + 1; x += GRID) {
        const a = proj(x, -PY, 0); const b = proj(x, PY, 0)
        ctx!.beginPath(); ctx!.moveTo(a.x, a.y); ctx!.lineTo(b.x, b.y); ctx!.stroke()
      }
      for (let y = -PY; y <= PY + 1; y += GRID) {
        const a = proj(-PX, y, 0); const b = proj(PX, y, 0)
        ctx!.beginPath(); ctx!.moveTo(a.x, a.y); ctx!.lineTo(b.x, b.y); ctx!.stroke()
      }

      /* 테두리 프레임 */
      ctx!.save()
      ctx!.shadowColor = C.cyan(0.7); ctx!.shadowBlur = 14
      ctx!.strokeStyle = C.cyan(0.6); ctx!.lineWidth = 1.6
      ctx!.beginPath()
      ctx!.moveTo(c1.x, c1.y); ctx!.lineTo(c2.x, c2.y)
      ctx!.lineTo(c3.x, c3.y); ctx!.lineTo(c4.x, c4.y)
      ctx!.closePath(); ctx!.stroke()
      ctx!.restore()

      /* 문설주(좌우 기둥) + 상인방(윗보) — 문의 구조 */
      ctx!.save()
      ctx!.shadowColor = C.cyan(0.75); ctx!.shadowBlur = 14
      ctx!.strokeStyle = C.cyan(0.85); ctx!.lineWidth = 3
      ctx!.beginPath(); ctx!.moveTo(c1.x, c1.y); ctx!.lineTo(c4.x, c4.y); ctx!.stroke()
      ctx!.beginPath(); ctx!.moveTo(c2.x, c2.y); ctx!.lineTo(c3.x, c3.y); ctx!.stroke()
      ctx!.lineWidth = 2.4
      ctx!.beginPath(); ctx!.moveTo(c1.x, c1.y); ctx!.lineTo(c2.x, c2.y); ctx!.stroke()
      ctx!.restore()

      /* 안쪽 프레임 — 문틀의 두께 */
      const i1 = proj(-PX + 16, -PY + 16, 0); const i2 = proj(PX - 16, -PY + 16, 0)
      const i3 = proj(PX - 16, PY - 16, 0); const i4 = proj(-PX + 16, PY - 16, 0)
      ctx!.strokeStyle = C.cyan(0.26); ctx!.lineWidth = 1
      ctx!.beginPath()
      ctx!.moveTo(i1.x, i1.y); ctx!.lineTo(i2.x, i2.y)
      ctx!.lineTo(i3.x, i3.y); ctx!.lineTo(i4.x, i4.y)
      ctx!.closePath(); ctx!.stroke()

      /* 파문 — 막 평면 위에서 퍼진다 (평면 좌표계로 변환해 그리기) */
      for (let i = ripples.length - 1; i >= 0; i--) {
        const r = ripples[i]; r.t++
        const life = r.big ? 34 : 24
        const k = r.t / life
        if (k >= 1) { ripples.splice(i, 1); continue }
        const o = proj(r.x, r.y, 0)
        const u = proj(r.x + 1, r.y, 0)
        const v = proj(r.x, r.y + 1, 0)
        ctx!.save()
        ctx!.transform(u.x - o.x, u.y - o.y, v.x - o.x, v.y - o.y, o.x, o.y)
        ctx!.strokeStyle = r.col((1 - k) * (r.big ? 0.8 : 0.5))
        ctx!.lineWidth = (r.big ? 2 : 1.4) / Math.max(0.2, o.s)
        const rad = (r.big ? 10 : 6) + k * (r.big ? 74 : 44)
        ctx!.beginPath(); ctx!.arc(0, 0, rad, 0, 7); ctx!.stroke()
        ctx!.restore()
      }
    }

    function draw(now: number) {
      ctx!.clearRect(0, 0, W, H)
      const tm = now * 0.001

      /* 카메라 워크 — 다층 사인 드리프트(비반복) + 요·피치 + 마우스 패럴럭스 */
      camZ = -760 - 150 * (0.5 + 0.5 * Math.cos(tm * 0.20))
        - 40 * Math.sin(tm * 0.053 + 2.1)
      camX = 20 * Math.sin(tm * 0.16) + 11 * Math.sin(tm * 0.067 + 0.8)
      camY = 12 * Math.sin(tm * 0.10 + 1.3) + 8 * Math.sin(tm * 0.047 + 2.4)
      /* 스크롤: 오브제(문·입자)는 페이지 속도로 그대로 위로 스크롤아웃.
         패럴랙스는 오직 배경 별필드만. */
      const sy = window.scrollY || 0
      camY += -sy
      const yaw = 0.09 * Math.sin(tm * 0.13) + mx * 0.07
      const pitchT = 0.06 * Math.sin(tm * 0.085 + 1.0) + my * 0.055
      yawO += (yaw - yawO) * 0.05
      pitchO += (pitchT - pitchO) * 0.05
      cosY = Math.cos(TH + yawO); sinY = Math.sin(TH + yawO)
      cp_ = Math.cos(pitchO); sp_ = Math.sin(pitchO)

      /* 은하 가스 글로우 */
      for (const nb of nebula) {
        nb.x += nb.dx; nb.y += nb.dy
        if (nb.x < -nb.r) { nb.x = W + nb.r }
        else if (nb.x > W + nb.r) { nb.x = -nb.r }
        if (nb.y < -nb.r) { nb.y = H + nb.r }
        else if (nb.y > H + nb.r) { nb.y = -nb.r }
        const na = nb.a * (0.75 + 0.25 * Math.sin(tm * nb.sp + nb.ph))
        const g = ctx!.createRadialGradient(nb.x, nb.y, 0, nb.x, nb.y, nb.r)
        g.addColorStop(0, nb.col(na))
        g.addColorStop(1, nb.col(0))
        ctx!.fillStyle = g
        ctx!.beginPath(); ctx!.arc(nb.x, nb.y, nb.r, 0, 7); ctx!.fill()
      }

      for (const s of stars) {
        s.x += s.dx
        if (s.x < -6) { s.x = W + 6 }
        else if (s.x > W + 6) { s.x = -6 }
        const a = s.base * (0.7 + 0.3 * Math.sin(tm * s.sp + s.ph))
        const col = s.tint ? C.cyan : C.star
        /* 배경(스페이스)만 패럴랙스 — 스크롤보다 느리게 따라오며 수직으로 랩 */
        let yy = s.y - sy * 0.4; yy = ((yy % H) + H) % H
        if (s.glow) {
          ctx!.fillStyle = col(a * 0.28)
          ctx!.beginPath(); ctx!.arc(s.x, yy, s.r * 3.6, 0, 7); ctx!.fill()
        }
        ctx!.fillStyle = col(a)
        ctx!.beginPath(); ctx!.arc(s.x, yy, s.r, 0, 7); ctx!.fill()
      }

      /* painter's algorithm — 막 너머 입자 → 멤브레인 → 막 앞 입자 */
      const far: any[] = []; const near: any[] = []
      for (const p of ambient) { ((p.phase === 'fly' && p.t >= TG) ? far : near).push(p) }

      for (const p of far) { drawParticle(p, tm) }
      drawMembrane()
      for (const p of near) { drawParticle(p, tm) }
    }

    let rafId = 0
    function loop(now: number) {
      for (const p of ambient) {
        if (p.phase === 'fly') {
          p.t += p.speed
          if (p.t >= TG) {
            if (!p.hit && p.fate !== 'pass') {
              p.hit = true; p.phase = p.fate
              addRipple(p.path.hx, p.path.hy, p.fate === 'bounce' ? C.deny : C.star, false)
            }
            else if (!p.crossed && p.fate === 'pass') {
              p.crossed = true
              addRipple(p.path.hx, p.path.hy, C.cyan, false)
            }
          }
          if (p.t > 1) { Object.assign(p, spawnAmbient(false)) }
        }
        else if (p.phase === 'bounce') {
          p.b += 0.022; p.alpha -= 0.02
          if (p.alpha <= 0) { Object.assign(p, spawnAmbient(false)) }
        }
        else {
          p.alpha -= 0.04
          if (p.alpha <= 0) { Object.assign(p, spawnAmbient(false)) }
        }
      }
      draw(now)
      rafId = requestAnimationFrame(loop)
    }

    function onResize() { resize() }
    function onScrollStatic() { draw(0) }

    resize()
    seedAmbient()
    window.addEventListener('resize', onResize)
    if (reduced) {
      draw(0)
      window.addEventListener('scroll', onScrollStatic, { passive: true })
    }
    else {
      window.addEventListener('pointermove', onPointerMove)
      rafId = requestAnimationFrame(loop)
    }

    return () => {
      cancelAnimationFrame(rafId)
      window.removeEventListener('resize', onResize)
      window.removeEventListener('scroll', onScrollStatic)
      window.removeEventListener('pointermove', onPointerMove)
    }
  }, [canvasRef])
}
