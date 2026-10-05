import { existsSync, readFileSync, statfsSync } from 'node:fs';
import { join } from 'node:path';
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';
import websocket from '@fastify/websocket';
import fastifyStatic from '@fastify/static';
import multipart from '@fastify/multipart';
import { join as joinPath } from 'node:path';
import { BlobStore } from './blobs/store.js';
import { terrainRoutes } from './terrain/routes.js';
import { attachmentRoutes } from './attachments/routes.js';
import { ZodError } from 'zod';
import { CORE_VERSION } from '@midden/core';
import { type Db, sqliteVersion } from './db/db.js';
import { migrate } from './db/migrate.js';
import { argon2Available } from './auth/password.js';
import { resolveSession, SESSION_COOKIE, type User } from './auth/sessions.js';
import { resolveApiToken } from './auth/tokens.js';
import { HttpError } from './lib/errors.js';
import { RuntimeRegistry } from './cases/runtime.js';
import { authRoutes } from './auth/routes.js';
import { oidcRoutes } from './auth/oidc.js';
import { caseRoutes } from './cases/routes.js';
import { wsRoutes } from './sync/ws.js';
import { adminRoutes } from './admin/routes.js';
import type { Config } from './config.js';

declare module 'fastify' {
  interface FastifyInstance {
    db: Db;
    cfg: Config;
    runtimes: RuntimeRegistry;
    blobs: BlobStore;
    /** Background ingests still running; awaited on close so tests and shutdown are deterministic. */
    pendingIngests: Set<Promise<unknown>>;
  }
  interface FastifyRequest {
    user: User | null;
    /** True when the request authenticated with an API key rather than a session cookie. */
    apiToken: boolean;
  }
}

export interface AppOptions {
  db: Db;
  cfg: Config;
  logger?: boolean | object;
  version?: string;
  https?: { cert: Buffer; key: Buffer } | undefined;
}

export function buildApp(opts: AppOptions): FastifyInstance {
  const { db, cfg } = opts;
  migrate(db);
  const app = Fastify({
    logger: opts.logger ?? false,
    trustProxy: cfg.trustProxy,
    bodyLimit: 32 * 1024 * 1024,
    ...(opts.https ? { https: opts.https } : {}),
  }) as unknown as FastifyInstance;
  const version = opts.version ?? CORE_VERSION;

  app.decorate('db', db);
  app.decorate('cfg', cfg);
  app.decorate('runtimes', new RuntimeRegistry(db));
  app.decorate('blobs', new BlobStore(db, cfg.blobDir ?? joinPath(cfg.dataDir, 'blobs')));
  app.decorate('pendingIngests', new Set<Promise<unknown>>());
  app.decorateRequest('user', null);
  app.decorateRequest('apiToken', false);

  app.register(cookie);
  app.register(rateLimit, { global: false });
  app.register(websocket, { options: { maxPayload: 8 * 1024 * 1024 } });
  app.register(multipart, {
    limits: { fileSize: cfg.maxUploadMb * 1_048_576, files: 1, fields: 10 },
  });

  // Session resolution for every request. An explicit bearer API key wins over the
  // cookie and must be valid — browsers cannot attach one unbidden, so no CSRF header
  // is required for API-key requests.
  app.addHook('onRequest', async (req) => {
    const bearer = /^Bearer (.+)$/.exec(req.headers.authorization ?? '')?.[1];
    if (bearer) {
      const user = resolveApiToken(db, bearer.trim());
      if (!user) throw new HttpError(401, 'Invalid API key', 'unauthorized');
      req.user = user;
      req.apiToken = true;
      return;
    }
    req.user = resolveSession(db, req.cookies[SESSION_COOKIE]);
  });

  // CSRF: browsers cannot add custom headers cross-site without CORS preflight, so requiring
  // one on every mutating API call blocks form-post and simple-request forgery.
  app.addHook('onRequest', async (req) => {
    if (!req.url.startsWith('/api/')) return;
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return;
    if (req.headers.upgrade) return;
    if (req.apiToken) return;
    if (req.headers['x-midden-client'] === undefined)
      throw new HttpError(403, 'Missing X-Midden-Client header', 'csrf');
  });

  app.setErrorHandler((raw: unknown, _req, reply) => {
    const err = raw as Error & { statusCode?: number };
    if (err instanceof HttpError)
      return reply
        .status(err.status)
        .send({ error: { code: err.code ?? 'error', message: err.message } });
    if (err instanceof ZodError) {
      const i = err.issues[0];
      return reply.status(400).send({
        error: {
          code: 'bad_request',
          message: i ? `${i.path.join('.') || 'body'}: ${i.message}` : 'invalid request',
        },
      });
    }
    const status = err.statusCode ?? 500;
    if (status >= 500) app.log.error(err);
    return reply.status(status).send({
      error: {
        code: status === 429 ? 'rate_limited' : 'error',
        message: status >= 500 ? 'Internal error' : err.message,
      },
    });
  });

  app.get('/api/health', async () => {
    let diskFreeMb: number | null;
    try {
      const s = statfsSync(cfg.dataDir);
      diskFreeMb = Math.round((Number(s.bavail) * Number(s.bsize)) / 1_048_576);
    } catch {
      diskFreeMb = null;
    }
    return {
      ok: true,
      version,
      node: process.version,
      arch: process.arch,
      sqlite: sqliteVersion(db),
      argon2: argon2Available(),
      diskFreeMb,
    };
  });

  app.register(authRoutes);
  app.register(oidcRoutes);
  app.register(caseRoutes);
  app.register(wsRoutes);
  app.register(adminRoutes);
  app.register(terrainRoutes);
  app.register(attachmentRoutes);

  registerStatic(app, version);

  app.addHook('onClose', async () => {
    await Promise.allSettled([...app.pendingIngests]);
    app.runtimes.closeAll();
  });

  return app;
}

/** Serve the web bundle with an injected runtime config and an SPA fallback. */
function registerStatic(app: FastifyInstance, version: string): void {
  const dir = app.cfg.publicDir;
  if (!dir || !existsSync(join(dir, 'index.html'))) {
    app.setNotFoundHandler((req, reply) => {
      if (req.url.startsWith('/api/'))
        return reply.status(404).send({ error: { code: 'notfound', message: 'Not found' } });
      return reply
        .status(404)
        .type('text/plain')
        .send('Midden server is running, but no web bundle is installed (MIDDEN_PUBLIC_DIR).');
    });
    return;
  }
  const raw = readFileSync(join(dir, 'index.html'), 'utf8');
  const inject = `<script>window.__MIDDEN__=${JSON.stringify({ mode: 'server', version, openCases: app.cfg.openCases })}</script></head>`;
  const html = raw.replace('</head>', inject);
  app.register(fastifyStatic, {
    root: dir,
    prefix: '/',
    index: false,
    wildcard: false,
    decorateReply: false,
  });
  const sendIndex = (_req: FastifyRequest, reply: FastifyReply): FastifyReply =>
    reply.type('text/html; charset=utf-8').header('cache-control', 'no-store').send(html);
  app.get('/', sendIndex);
  app.setNotFoundHandler((req, reply) => {
    if (req.url.startsWith('/api/'))
      return reply.status(404).send({ error: { code: 'notfound', message: 'Not found' } });
    if (req.method !== 'GET')
      return reply.status(404).send({ error: { code: 'notfound', message: 'Not found' } });
    return sendIndex(req, reply);
  });
}

export function requireUser(req: FastifyRequest): User {
  if (!req.user) throw new HttpError(401, 'Sign in required', 'unauthorized');
  return req.user;
}

export function requireAdmin(req: FastifyRequest): User {
  const u = requireUser(req);
  if (u.role !== 'admin') throw new HttpError(403, 'Admin only', 'forbidden');
  return u;
}
