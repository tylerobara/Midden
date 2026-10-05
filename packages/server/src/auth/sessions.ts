import { createHash, randomBytes } from 'node:crypto';
import type { Db } from '../db/db.js';
import { newId, nowIso } from '../lib/ids.js';

export type GlobalRole = 'admin' | 'analyst' | 'viewer';

export interface User {
  id: string;
  username: string;
  displayName: string;
  role: GlobalRole;
  disabled: boolean;
  mustChangePassword: boolean;
  createdAt: string;
  hasPassword: boolean;
  oidcSub: string | null;
}

interface UserRow {
  id: string;
  username: string;
  display_name: string;
  password_hash: string | null;
  role: GlobalRole;
  oidc_sub: string | null;
  disabled: number;
  must_change_password: number;
  created_at: string;
}

export const SESSION_COOKIE = 'midden_session';
export const SESSION_TTL_MS = 14 * 24 * 3600 * 1000;

export const hashToken = (t: string): string => createHash('sha256').update(t).digest('hex');

export function rowToUser(r: UserRow): User {
  return {
    id: r.id,
    username: r.username,
    displayName: r.display_name,
    role: r.role,
    disabled: !!r.disabled,
    mustChangePassword: !!r.must_change_password,
    createdAt: r.created_at,
    hasPassword: !!r.password_hash,
    oidcSub: r.oidc_sub,
  };
}

export function findUserByUsername(
  db: Db,
  username: string,
): (User & { passwordHash: string | null }) | null {
  const r = db.get<UserRow>('SELECT * FROM users WHERE username = ?', username);
  return r ? { ...rowToUser(r), passwordHash: r.password_hash } : null;
}

export function findUserById(db: Db, id: string): User | null {
  const r = db.get<UserRow>('SELECT * FROM users WHERE id = ?', id);
  return r ? rowToUser(r) : null;
}

export function listUsers(db: Db): User[] {
  return db.all<UserRow>('SELECT * FROM users ORDER BY username').map(rowToUser);
}

export interface CreateUserInput {
  username: string;
  displayName: string;
  role: GlobalRole;
  passwordHash?: string | null | undefined;
  oidcSub?: string | null | undefined;
  mustChangePassword?: boolean | undefined;
}

export function createUser(db: Db, input: CreateUserInput): User {
  const id = newId('u');
  db.run(
    'INSERT INTO users (id, username, display_name, password_hash, role, oidc_sub, disabled, must_change_password, created_at) VALUES (?,?,?,?,?,?,0,?,?)',
    id,
    input.username,
    input.displayName || input.username,
    input.passwordHash ?? null,
    input.role,
    input.oidcSub ?? null,
    input.mustChangePassword ? 1 : 0,
    nowIso(),
  );
  return findUserById(db, id)!;
}

export function countUsers(db: Db): number {
  return Number(db.get<{ n: number }>('SELECT COUNT(*) AS n FROM users')?.n ?? 0);
}

/** Create a session and return the raw cookie token (only ever shown once). */
export function createSession(
  db: Db,
  userId: string,
  meta: { ip?: string | undefined; ua?: string | undefined } = {},
): string {
  const token = randomBytes(32).toString('base64url');
  const now = Date.now();
  db.run(
    'INSERT INTO sessions (id, user_id, created_at, expires_at, last_seen_at, ip, ua) VALUES (?,?,?,?,?,?,?)',
    hashToken(token),
    userId,
    new Date(now).toISOString(),
    new Date(now + SESSION_TTL_MS).toISOString(),
    new Date(now).toISOString(),
    meta.ip ?? null,
    meta.ua?.slice(0, 200) ?? null,
  );
  return token;
}

/** Resolve a cookie token to its user, sliding the expiry. */
export function resolveSession(db: Db, token: string | undefined): User | null {
  if (!token) return null;
  const id = hashToken(token);
  const row = db.get<{ user_id: string; expires_at: string; last_seen_at: string }>(
    'SELECT user_id, expires_at, last_seen_at FROM sessions WHERE id = ?',
    id,
  );
  if (!row) return null;
  const now = Date.now();
  if (Date.parse(row.expires_at) < now) {
    db.run('DELETE FROM sessions WHERE id = ?', id);
    return null;
  }
  if (now - Date.parse(row.last_seen_at) > 60_000) {
    db.run(
      'UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?',
      new Date(now).toISOString(),
      new Date(now + SESSION_TTL_MS).toISOString(),
      id,
    );
  }
  const user = findUserById(db, row.user_id);
  if (!user || user.disabled) return null;
  return user;
}

export function destroySession(db: Db, token: string | undefined): void {
  if (token) db.run('DELETE FROM sessions WHERE id = ?', hashToken(token));
}

export function destroyUserSessions(db: Db, userId: string): void {
  db.run('DELETE FROM sessions WHERE user_id = ?', userId);
}

export function purgeExpiredSessions(db: Db): number {
  return Number(db.run('DELETE FROM sessions WHERE expires_at < ?', nowIso()).changes);
}

/* ---- login backoff (per username, on top of the per-IP rate limit) ---- */

export function loginLockedUntil(db: Db, username: string): number | null {
  const r = db.get<{ locked_until: string | null }>(
    'SELECT locked_until FROM login_failures WHERE username = ?',
    username,
  );
  if (!r?.locked_until) return null;
  const t = Date.parse(r.locked_until);
  return t > Date.now() ? t : null;
}

export function recordLoginFailure(db: Db, username: string): void {
  const r = db.get<{ count: number }>(
    'SELECT count FROM login_failures WHERE username = ?',
    username,
  );
  const count = Number(r?.count ?? 0) + 1;
  // 5 free attempts, then 2^(n-5) seconds up to 15 minutes
  const delay = count > 5 ? Math.min(900, 2 ** (count - 5)) * 1000 : 0;
  const until = delay ? new Date(Date.now() + delay).toISOString() : null;
  db.run(
    'INSERT INTO login_failures (username, count, locked_until) VALUES (?,?,?) ON CONFLICT(username) DO UPDATE SET count = excluded.count, locked_until = excluded.locked_until',
    username,
    count,
    until,
  );
}

export function clearLoginFailures(db: Db, username: string): void {
  db.run('DELETE FROM login_failures WHERE username = ?', username);
}
