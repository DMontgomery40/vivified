import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  base: '/admin/ui/',
  resolve: {
    // Ensure a single React/DOM copy is bundled and referenced
    dedupe: ['react', 'react-dom'],
    alias: {
      react: path.resolve(__dirname, 'node_modules/react'),
      'react-dom': path.resolve(__dirname, 'node_modules/react-dom'),
      'react/jsx-runtime': path.resolve(__dirname, 'node_modules/react/jsx-runtime'),
      'react/jsx-dev-runtime': path.resolve(__dirname, 'node_modules/react/jsx-dev-runtime'),
    }
  },
  css: {
    // Prevent PostCSS from walking up outside the project (avoids permission errors)
    postcss: {}
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: true,
    minify: 'esbuild'
  },
  server: {
    port: 3000,
    proxy: {
      '/admin': 'http://localhost:8080',
      '/fax': 'http://localhost:8080',
      '/inbound': 'http://localhost:8080'
    }
  }
})
