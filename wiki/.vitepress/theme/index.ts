import DefaultTheme from 'vitepress/theme'
import type { Theme } from 'vitepress'
import { useRoute } from 'vitepress'
import { nextTick, onMounted, watch } from 'vue'
import mediumZoom from 'medium-zoom'
import type { Zoom } from 'medium-zoom'
import { installDiagramZoom } from './diagram-zoom'
import './custom.css'

// Daytona-inspired dark theme. Click-to-zoom: medium-zoom for raster images,
// a custom SVG overlay (pan + wheel-zoom) for Mermaid diagrams.
export default {
  extends: DefaultTheme,
  setup() {
    const route = useRoute()
    // Reuse a single medium-zoom instance across navigations; detaching stale
    // targets before re-attaching avoids leaking observers/listeners per route.
    let zoom: Zoom | undefined
    const refresh = () => {
      if (!zoom)
        zoom = mediumZoom({ background: 'rgba(13,17,23,0.92)' })
      zoom.detach()
      zoom.attach('.vp-doc img')
      // Custom overlay zoom for rendered Mermaid SVGs.
      installDiagramZoom()
    }
    onMounted(() => nextTick(refresh))
    watch(
      () => route.path,
      () => nextTick(refresh),
    )
  },
} satisfies Theme
