import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { CORE_VERSION } from '@midden/core';
import { loadConfig } from './config.js';
import { openDatabase } from './db/db.js';
import { buildApp } from './app.js';
import { argon2Available } from './auth/password.js';
import { seedAdmin } from './auth/seed.js';
import { runCli } from './cli.js';

async function main(): Promise<void> {
  const cfg = loadConfig();
  if (!argon2Available()) {
    console.error('FATAL: crypto.argon2 is unavailable. Use Node 24+ built with OpenSSL >= 3.2.');
    process.exit(1);
  }
  mkdirSync(cfg.dataDir, { recursive: true });
  const [, , cmd, ...args] = process.argv;
  if (cmd && cmd !== 'serve') {
    process.exit(await runCli(cfg, cmd, args));
  }
  const db = openDatabase(join(cfg.dataDir, 'midden.db'));
  const app = buildApp({
    db,
    cfg,
    logger: { level: cfg.logLevel },
    version: process.env.MIDDEN_VERSION || CORE_VERSION,
    ...(cfg.tls
      ? { https: { cert: readFileSync(cfg.tls.cert), key: readFileSync(cfg.tls.key) } }
      : {}),
  });
  const seeded = seedAdmin(db, cfg);
  if (seeded) app.log.warn(seeded);

  const evict = setInterval(() => app.runtimes.evictIdle(), 60_000);
  const shutdown = async (): Promise<void> => {
    clearInterval(evict);
    await app.close();
    db.close();
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown());
  process.on('SIGTERM', () => void shutdown());

  await app.listen({ port: cfg.port, host: cfg.host });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
