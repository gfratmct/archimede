import { defineConfig } from 'vite'
import solid from 'vite-plugin-solid'

export default defineConfig({
  plugins: [solid()],
  server: {
    port: 5173,
    proxy: {
      '/v1': 'http://127.0.0.1:7432',
      '/health': 'http://127.0.0.1:7432',
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})
