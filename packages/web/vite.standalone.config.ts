import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { viteSingleFile } from 'vite-plugin-singlefile';
import { readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as {
  version: string;
};

/**
 * Standalone build: one self-contained HTML file that runs from file:// with no
 * server. Everything (JS, CSS, workers) is inlined; nothing is fetched at runtime.
 */
export default defineConfig({
  plugins: [react(), viteSingleFile()],
  define: {
    __MIDDEN_MODE__: JSON.stringify('standalone'),
    __MIDDEN_VERSION__: JSON.stringify(process.env.MIDDEN_VERSION || pkg.version),
  },
  build: {
    outDir: 'dist-standalone',
    sourcemap: false,
    assetsInlineLimit: 100_000_000,
    cssCodeSplit: false,
  },
});
