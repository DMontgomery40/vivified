import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig(({ mode }) => {
  const isDev = mode === 'development'
  return {
    plugins: [react()],
    // In dev, serve at root to avoid proxy collisions with '/admin/ui/'.
    // In build, emit under '/admin/ui/' for production hosting.
    base: isDev ? '/' : '/admin/ui/',
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
      port: 5173,
      // Rely on absolute API base via VITE_CORE_URL from the client; no proxy to avoid
      // intercepting '/admin/ui/' which is the app shell path.
      proxy: {}
    }
  }
})
