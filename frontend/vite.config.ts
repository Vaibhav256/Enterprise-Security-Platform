import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
    },
    // Force browser to always get fresh files in dev
    headers: {
      'Cache-Control': 'no-store',
    },
  },
  build: {
    // Enable minification
    minify: 'esbuild',
    // Optimize chunk strategy
    rollupOptions: {
      output: {
        manualChunks: {
          // Core React libs
          'react-vendor': ['react', 'react-dom'],
          'router-vendor': ['react-router-dom'],
          
          // Heavy libraries
          'chart-vendor': ['recharts'],
          'animation-vendor': ['framer-motion'],
          
          // UI libraries
          'ui-vendor': ['lucide-react'],
          
          // HTTP and WebSocket
          'http-vendor': ['axios', 'socket.io-client'],
        },
        // Optimize chunk file names
        chunkFileNames: 'assets/[name]-[hash].js',
        entryFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]',
      },
    },
    // Increase chunk size warning limit
    chunkSizeWarningLimit: 800,
    // Enable CSS code splitting
    cssCodeSplit: true,
    // Source maps for better debugging (disable in production)
    sourcemap: false,
  },
  // Optimize dependencies
  optimizeDeps: {
    include: [
      'react',
      'react-dom',
      'react-router-dom',
      'axios',
      'framer-motion',
      'lucide-react',
    ],
  },
})

