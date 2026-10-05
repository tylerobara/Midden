import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as {
  version: string;
};

export default defineConfig({
  plugins: [react()],
  define: {
    __MIDDEN_MODE__: JSON.stringify('server'),
    // Release builds stamp MIDDEN_VERSION with the git tag (see Dockerfile); dev falls back to package.json.
    __MIDDEN_VERSION__: JSON.stringify(process.env.MIDDEN_VERSION || pkg.version),
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
  server: {
    proxy: {
      // The sync socket lives at /api/ws and must come first. Vite walks these entries in order
      // and stops at the first one whose path matches, but only proxies the upgrade when that
      // entry sets `ws`. Behind a plain '/api' entry the upgrade is neither proxied nor refused:
      // the socket is left hanging and the client sits on "connecting".
      '/api/ws': { target: 'ws://localhost:8080', ws: true },
      '/api': 'http://localhost:8080',
    },
  },
});
