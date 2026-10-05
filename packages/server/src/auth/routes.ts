import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { randomBytes } from 'node:crypto';
import { requireAdmin, requireUser } from '../app.js';
import { HttpError, badRequest, notFound } from '../lib/errors.js';
import { hashPassword, verifyPassword } from './password.js';
import {
  clearLoginFailures,
  createSession,
  createUser,
  destroySession,
  destroyUserSessions,
  findUserById,
  findUserByUsername,
  listUsers,
  loginLockedUntil,
  recordLoginFailure,
  SESSION_COOKIE,
  type User,
} from './sessions.js';
import {
  countApiTokens,
  createApiToken,
  listApiTokens,
  MAX_TOKENS_PER_USER,
  revokeApiToken,
} from './tokens.js';

const Login = z.object({
  username: z.string().trim().min(1).max(64),
  password: z.string().min(1).max(1024),
});
const Password = z.object({
  current: z.string().max(1024).optional(),
  next: z.string().min(10).max(1024),
});
const Role = z.enum(['admin', 'analyst', 'viewer']);
const CreateUser = z.object({
  username: z
    .string()
    .trim()
    .min(1)
    .max(64)
    .regex(/^[A-Za-z0-9._@-]+$/, 'letters, digits, . _ @ - only'),
  displayName: z.string().trim().max(120).default(''),
  role: Role.default('analyst'),
  password: z.string().min(10).max(1024).optional(),
});
const PatchUser = z.object({
  displayName: z.string().trim().max(120).optional(),
  role: Role.optional(),
  disabled: z.boolean().optional(),
  password: z.string().min(10).max(1024).optional(),
});
const TokenName = z.object({ name: z.string().trim().min(1).max(80) });

export function publicUser(u: User): Omit<User, 'oidcSub'> {
  const { oidcSub: _o, ...rest } = u;
  return rest;
}

function setSessionCookie(
  app: FastifyInstance,
  req: FastifyRequest,
  reply: FastifyReply,
  token: string,
): void {
  const secure =
    app.cfg.sessionSecure === 'auto'
      ? req.protocol === 'https' || (app.cfg.publicOrigin?.startsWith('https://') ?? false)
      : app.cfg.sessionSecure;
  reply.setCookie(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure,
    path: '/',
    maxAge: 14 * 24 * 3600,
  });
}

export async function authRoutes(app: FastifyInstance): Promise<void> {
  const argon = { memory: app.cfg.argon2MemoryKiB, passes: 3, parallelism: 1, tagLength: 32 };

  app.post(
    '/api/auth/login',
    { config: { rateLimit: { max: app.cfg.loginRateLimit, timeWindow: '1 minute' } } },
    async (req, reply) => {
      const { username, password } = Login.parse(req.body);
      const locked = loginLockedUntil(app.db, username);
      if (locked)
        throw new HttpError(
          429,
          `Too many failed attempts. Try again in ${Math.ceil((locked - Date.now()) / 1000)}s`,
          'locked',
        );
      const user = findUserByUsername(app.db, username);
      const ok =
        !!user &&
        !user.disabled &&
        !!user.passwordHash &&
        verifyPassword(password, user.passwordHash);
      if (!ok || !user) {
        recordLoginFailure(app.db, username);
        throw new HttpError(401, 'Invalid username or password', 'bad_credentials');
      }
      clearLoginFailures(app.db, username);
      const token = createSession(app.db, user.id, { ip: req.ip, ua: req.headers['user-agent'] });
      setSessionCookie(app, req, reply, token);
      return { user: publicUser(user), mustChangePassword: user.mustChangePassword };
    },
  );

  app.post('/api/auth/logout', async (req, reply) => {
    destroySession(app.db, req.cookies[SESSION_COOKIE]);
    reply.clearCookie(SESSION_COOKIE, { path: '/' });
    return { ok: true };
  });

  app.get('/api/auth/me', async (req) => {
    const user = requireUser(req);
    return {
      user: publicUser(user),
      mustChangePassword: user.mustChangePassword,
      openCases: app.cfg.openCases,
      oidc: !!app.cfg.oidc,
    };
  });

  app.post('/api/auth/password', async (req) => {
    const user = requireUser(req);
    const body = Password.parse(req.body);
    const full = findUserByUsername(app.db, user.username)!;
    if (!user.mustChangePassword) {
      if (!body.current || !full.passwordHash || !verifyPassword(body.current, full.passwordHash))
        throw new HttpError(403, 'Current password is wrong', 'bad_credentials');
    }
    app.db.run(
      'UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?',
      hashPassword(body.next, argon),
      user.id,
    );
    return { ok: true };
  });

  /* ---- API tokens ---- */

  app.get('/api/auth/tokens', async (req) => {
    const user = requireUser(req);
    return { tokens: listApiTokens(app.db, user.id) };
  });

  app.post('/api/auth/tokens', async (req, reply) => {
    const user = requireUser(req);
    const { name } = TokenName.parse(req.body);
    if (countApiTokens(app.db, user.id) >= MAX_TOKENS_PER_USER)
      throw new HttpError(
        409,
        `At most ${MAX_TOKENS_PER_USER} API keys per user`,
        'too_many_tokens',
      );
    const created = createApiToken(app.db, user.id, name);
    return reply.status(201).send({ ...created.meta, key: created.key });
  });

  app.delete<{ Params: { id: string } }>('/api/auth/tokens/:id', async (req) => {
    const user = requireUser(req);
    if (!revokeApiToken(app.db, user.id, req.params.id)) throw notFound('No such API key');
    return { ok: true };
  });

  /* ---- user administration ---- */

  app.get('/api/users', async (req) => {
    requireUser(req);
    return { users: listUsers(app.db).map(publicUser) };
  });

  app.post('/api/users', async (req, reply) => {
    requireAdmin(req);
    const body = CreateUser.parse(req.body);
    if (findUserByUsername(app.db, body.username))
      throw new HttpError(409, 'Username already taken', 'conflict');
    const temp = body.password ?? randomBytes(9).toString('base64url');
    const user = createUser(app.db, {
      username: body.username,
      displayName: body.displayName || body.username,
      role: body.role,
      passwordHash: hashPassword(temp, argon),
      mustChangePassword: true,
    });
    reply.status(201);
    return { user: publicUser(user), temporaryPassword: body.password ? undefined : temp };
  });

  app.patch<{ Params: { id: string } }>('/api/users/:id', async (req) => {
    const admin = requireAdmin(req);
    const target = findUserById(app.db, req.params.id);
    if (!target) throw notFound('No such user');
    const body = PatchUser.parse(req.body);
    if (
      target.id === admin.id &&
      ((body.role !== undefined && body.role !== 'admin') || body.disabled)
    )
      throw badRequest('You cannot demote or disable your own account');
    if (body.displayName !== undefined)
      app.db.run(
        'UPDATE users SET display_name = ? WHERE id = ?',
        body.displayName || target.username,
        target.id,
      );
    if (body.role !== undefined)
      app.db.run('UPDATE users SET role = ? WHERE id = ?', body.role, target.id);
    if (body.disabled !== undefined) {
      app.db.run('UPDATE users SET disabled = ? WHERE id = ?', body.disabled ? 1 : 0, target.id);
      if (body.disabled) destroyUserSessions(app.db, target.id);
    }
    if (body.password !== undefined) {
      app.db.run(
        'UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?',
        hashPassword(body.password, argon),
        target.id,
      );
      destroyUserSessions(app.db, target.id);
    }
    return { user: publicUser(findUserById(app.db, target.id)!) };
  });
}
