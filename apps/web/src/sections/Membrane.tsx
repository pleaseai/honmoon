import { useRef } from 'react'
import { useMembrane } from '../hooks/useMembrane'

/**
 * Full-viewport fixed background canvas (`#gate3d`). Rendered once at the top of
 * the page as a fixed layer behind all content (z-index: -1 via globals.css),
 * not as an in-flow section box.
 */
export function Membrane() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  useMembrane(canvasRef)
  return <canvas id="gate3d" ref={canvasRef} aria-hidden="true"></canvas>
}
