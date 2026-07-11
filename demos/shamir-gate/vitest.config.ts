import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    // Playwright a11y specs live under e2e/ and run via `npm run test:a11y`.
    // Keep them out of the Vitest unit run so the two runners don't collide.
    exclude: ['**/node_modules/**', '**/dist/**', 'e2e/**']
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src')
    }
  }
});
