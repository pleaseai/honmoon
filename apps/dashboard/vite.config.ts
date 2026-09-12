import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Built assets are embedded into the Rust data-plane binary via rust-embed
  // and served by the management API.
  build: {
    outDir: 'dist',
  },
  // In `vite dev`, forward API calls to a locally-running management API
  // (`honmoon gateway --mgmt-addr 127.0.0.1:8444`). `/login` is proxied too:
  // the API requires the management token (#173), and that route is what hands
  // the dev server's dashboard its session secret — without it every proxied
  // `/api` call answers 401 and the HMR dashboard cannot log in. The secret
  // lands in `sessionStorage` for the *dev* origin (#188), so logging in on
  // `:5173` is separate from logging in on `:8444`.
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8444',
      '/healthz': 'http://127.0.0.1:8444',
      '/login': 'http://127.0.0.1:8444',
    },
  },
})
