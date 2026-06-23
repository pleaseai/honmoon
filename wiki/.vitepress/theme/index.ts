import DefaultTheme from 'vitepress/theme'
import type { Theme } from 'vitepress'
import { useRoute } from 'vitepress'
import { nextTick, onMounted, watch } from 'vue'
import mediumZoom from 'medium-zoom'
import { installDiagramZoom } from './diagram-zoom'
import './custom.css'

// Daytona-inspired dark theme. Click-to-zoom: medium-zoom for raster images,
// a custom SVG overlay (pan + wheel-zoom) for Mermaid diagrams.
export default {
  extends: DefaultTheme,
  setup() {
    const route = useRoute()
    const refresh = () => {
      // medium-zoom for any <img> in the article body.
      mediumZoom('.vp-doc img', { background: 'rgba(13,17,23,0.92)' })
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
