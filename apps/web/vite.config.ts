import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Static marketing landing page (apps/web). Unlike apps/dashboard this app has
// no management-API backend, so no dev proxy / rust-embed wiring is needed.
// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: 'dist',
  },
})
