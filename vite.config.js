import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // The API (app/main.py) serves this folder in production, and Vercel puts it on its CDN.
  build: { outDir: 'static', emptyOutDir: true },
  server: {
    port: 5173,
    // Lets the dev server be reached through an ngrok tunnel (a leading dot also allows other ngrok-free.dev subdomains).
    allowedHosts: ['.ngrok-free.dev'],
    proxy: { '/api': { target: process.env.VITE_API_PROXY || 'http://localhost:8000', changeOrigin: true } },
  },
})
