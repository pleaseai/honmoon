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
  // (`honmoon gateway --mgmt-addr 127.0.0.1:8444`).
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8444',
      '/healthz': 'http://127.0.0.1:8444',
    },
  },
})
