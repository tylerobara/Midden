import { randomBytes } from 'node:crypto';
import type { Db } from '../db/db.js';
import { newId, nowIso } from '../lib/ids.js';
import { findUserById, hashToken, type User } from './sessions.js';

export const API_TOKEN_PREFIX = 'mk_';
export const MAX_TOKENS_PER_USER = 20;

export interface ApiTokenMeta {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt: string | null;
}

/** Create a token, store only its hash, and return the raw key (shown once). */
export function createApiToken(
  db: Db,
  userId: string,
  name: string,
): { id: string; key: string; meta: ApiTokenMeta } {
  const id = newId('tok');
  const key = API_TOKEN_PREFIX + randomBytes(32).toString('base64url');
  db.run(
    'INSERT INTO api_tokens (id, token_hash, user_id, name, created_at) VALUES (?,?,?,?,?)',
    id,
    hashToken(key),
    userId,
    name,
    nowIso(),
  );
  return { id, key, meta: { id, name, createdAt: nowIso(), lastUsedAt: null } };
}

/** Resolve a raw bearer token to its user; refreshes last_used at most once a minute. */
export function resolveApiToken(db: Db, rawKey: string): User | null {
  const row = db.get<{ id: string; user_id: string; last_used_at: string | null }>(
    'SELECT id, user_id, last_used_at FROM api_tokens WHERE token_hash = ?',
    hashToken(rawKey),
  );
  if (!row) return null;
  if (!row.last_used_at || Date.now() - Date.parse(row.last_used_at) > 60_000)
    db.run('UPDATE api_tokens SET last_used_at = ? WHERE id = ?', nowIso(), row.id);
  const user = findUserById(db, row.user_id);
  return user && !user.disabled ? user : null;
}

export function listApiTokens(db: Db, userId: string): ApiTokenMeta[] {
  return db
    .all<{ id: string; name: string; created_at: string; last_used_at: string | null }>(
      'SELECT id, name, created_at, last_used_at FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC',
      userId,
    )
    .map((r) => ({ id: r.id, name: r.name, createdAt: r.created_at, lastUsedAt: r.last_used_at }));
}

/** Delete a token owned by userId. Returns false when the id is not theirs. */
export function revokeApiToken(db: Db, userId: string, id: string): boolean {
  return (
    Number(db.run('DELETE FROM api_tokens WHERE id = ? AND user_id = ?', id, userId).changes) > 0
  );
}

export function countApiTokens(db: Db, userId: string): number {
  return Number(
    db.get<{ n: number }>('SELECT COUNT(*) AS n FROM api_tokens WHERE user_id = ?', userId)?.n ?? 0,
  );
}
