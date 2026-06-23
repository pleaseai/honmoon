// Click-to-zoom overlay for Mermaid SVG diagrams: opens the diagram in a
// full-screen overlay with mouse-wheel zoom and drag-to-pan. Pure DOM, no deps,
// SSR-safe (guards on `document`).

let overlay: HTMLDivElement | null = null

function buildOverlay(): HTMLDivElement {
  const el = document.createElement('div')
  el.className = 'diagram-overlay'
  el.innerHTML = `
    <div class="diagram-overlay__hint">scroll to zoom · drag to pan · esc / click to close</div>
    <div class="diagram-overlay__stage"></div>`
  el.addEventListener('click', (e) => {
    if (e.target === el || (e.target as HTMLElement).classList.contains('diagram-overlay__hint'))
      close()
  })
  document.body.appendChild(el)
  return el
}

function close() {
  if (overlay) overlay.classList.remove('is-open')
  document.removeEventListener('keydown', onKey)
}

function onKey(e: KeyboardEvent) {
  if (e.key === 'Escape') close()
}

function open(svg: SVGElement) {
  if (typeof document === 'undefined') return
  if (!overlay) overlay = buildOverlay()
  const stage = overlay.querySelector('.diagram-overlay__stage') as HTMLDivElement
  stage.innerHTML = ''
  const clone = svg.cloneNode(true) as SVGElement
  clone.removeAttribute('style')
  clone.style.maxWidth = 'none'
  clone.style.maxHeight = 'none'
  stage.appendChild(clone)

  // Pan + zoom state.
  let scale = 1
  let x = 0
  let y = 0
  let dragging = false
  let sx = 0
  let sy = 0
  const apply = () => {
    clone.style.transform = `translate(${x}px, ${y}px) scale(${scale})`
  }
  stage.onwheel = (e: WheelEvent) => {
    e.preventDefault()
    scale = Math.min(8, Math.max(0.3, scale * (e.deltaY < 0 ? 1.12 : 0.89)))
    apply()
  }
  stage.onpointerdown = (e: PointerEvent) => {
    dragging = true
    sx = e.clientX - x
    sy = e.clientY - y
    stage.setPointerCapture(e.pointerId)
  }
  stage.onpointermove = (e: PointerEvent) => {
    if (!dragging) return
    x = e.clientX - sx
    y = e.clientY - sy
    apply()
  }
  stage.onpointerup = () => {
    dragging = false
  }
  apply()

  overlay.classList.add('is-open')
  document.addEventListener('keydown', onKey)
}

export function installDiagramZoom() {
  if (typeof document === 'undefined') return
  const diagrams = document.querySelectorAll<SVGElement>('.vp-doc .mermaid svg, .vp-doc svg[id^="mermaid"]')
  diagrams.forEach((svg) => {
    if (svg.dataset.zoomBound) return
    svg.dataset.zoomBound = '1'
    svg.style.cursor = 'zoom-in'
    svg.addEventListener('click', () => open(svg))
  })
}
