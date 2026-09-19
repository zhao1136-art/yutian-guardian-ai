import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// dev：vite 起 5173，把 API 代理到后端 8567
// build：产物输出到父级 static_web，由后端同端口托管
export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    outDir: '../static_web',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/health': { target: 'http://127.0.0.1:8567', changeOrigin: true },
      '/predict': { target: 'http://127.0.0.1:8567', changeOrigin: true },
      '/monitor': { target: 'http://127.0.0.1:8567', changeOrigin: true },
      '/explain': { target: 'http://127.0.0.1:8567', changeOrigin: true },
    },
  },
})