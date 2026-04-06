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
      '@': path.resolve(__dirname, './src'),
      '@crypto': path.resolve(__dirname, './src/crypto'),
      '@visualization': path.resolve(__dirname, './src/visualization')
    }
  }
});
