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
})
