import { defineConfig } from 'vite';
import path from 'path';

export default defineConfig({
  root: '.',
  base: '/crypto-lab-shamir-gate/',
  server: {
    port: 5173,
    open: true
  },
  build: {
    outDir: 'dist',
    sourcemap: true
  },
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src'),
      '@crypto': path.resolve(import.meta.dirname, './src/crypto'),
      '@visualization': path.resolve(import.meta.dirname, './src/visualization')
    }
  }
});
