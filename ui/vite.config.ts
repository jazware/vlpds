import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { vlpdsDocs } from './docs-build/plugin.mjs'

// Node's environment, without pulling in @types/node for one variable.
declare const process: { env: Record<string, string | undefined> }

// `just dev-ui` runs this against a local vlpds (VLPDS_URL, default :2620). /xrpc proxies
// websockets too, for the console's subscribeRepos tail.
const target = process.env.VLPDS_URL ?? 'http://127.0.0.1:2620'
const proxy = Object.fromEntries(
  ['/xrpc', '/oauth', '/metrics', '/.well-known'].map((p) => [p, { target, changeOrigin: false, ws: p === '/xrpc' }]),
)

export default defineConfig({
  plugins: [react(), vlpdsDocs()],
  base: '/',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // no inline polyfill script: the page CSP is script-src 'self'
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    chunkSizeWarningLimit: 800,
  },
  server: { port: 5620, proxy },
})
