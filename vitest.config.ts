import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

const core = fileURLToPath(new URL('./packages/core/src/index.ts', import.meta.url));

export default defineConfig({
  resolve: {
    alias: { '@midden/core': core },
  },
  test: {
    projects: [
      {
        extends: true,
        test: {
          name: 'core',
          root: 'packages/core',
          environment: 'node',
          include: ['src/**/*.test.ts'],
        },
      },
      {
        extends: true,
        test: {
          name: 'server',
          root: 'packages/server',
          environment: 'node',
          include: ['src/**/*.test.ts'],
        },
      },
      {
        extends: true,
        test: {
          name: 'web',
          root: 'packages/web',
          environment: 'jsdom',
          include: ['src/**/*.test.{ts,tsx}'],
          setupFiles: ['./src/test/setup.ts'],
        },
        define: {
          __MIDDEN_MODE__: JSON.stringify('test'),
          __MIDDEN_VERSION__: JSON.stringify('0.0.0-test'),
        },
      },
    ],
  },
});
