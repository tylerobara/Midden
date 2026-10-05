/**
 * CLI login handshake: the `midden` CLI fetches a one-time challenge, opens the
 * web app at #/cli?challenge=... and polls; the signed-in browser exchanges the
 * challenge for a fresh API key. Challenges live only in memory — they are
 * single-use, expire quickly, and the id itself is the capability.
 */
import { randomBytes } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { requireUser } from '../app.js';
import { HttpError } from '../lib/errors.js';
import { countApiTokens, createApiToken, MAX_TOKENS_PER_USER } from './tokens.js';

interface Challenge {
  expires: number;
  token?: string;
  tokenId?: string;
  username?: string;
}

const CHALLENGE_TTL_MS = 120_000;
const Grant = z.object({ challenge: z.string().regex(/^[a-f0-9]{32}$/) });
const rate = { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } };

export async function cliAuthRoutes(app: FastifyInstance): Promise<void> {
  const challenges = new Map<string, Challenge>();
  const sweep = (): void => {
    for (const [id, c] of challenges) if (c.expires < Date.now()) challenges.delete(id);
  };

  app.get('/api/auth/cli/challenge', rate, async () => {
    sweep();
    const id = randomBytes(16).toString('hex');
    challenges.set(id, { expires: Date.now() + CHALLENGE_TTL_MS });
    return { challenge: id, expiresIn: CHALLENGE_TTL_MS / 1000 };
  });

  app.post('/api/auth/cli/authorize', rate, async (req) => {
    const user = requireUser(req);
    const { challenge } = Grant.parse(req.body);
    const c = challenges.get(challenge);
    if (!c || c.expires < Date.now() || c.token)
      throw new HttpError(
        400,
        'Sign-in request expired or already used; rerun the CLI.',
        'bad_challenge',
      );
    if (countApiTokens(app.db, user.id) >= MAX_TOKENS_PER_USER)
      throw new HttpError(
        409,
        `At most ${MAX_TOKENS_PER_USER} API keys per user`,
        'too_many_tokens',
      );
    const t = createApiToken(app.db, user.id, 'midden CLI');
    Object.assign(c, { token: t.key, tokenId: t.id, username: user.username });
    return { ok: true, username: user.username };
  });

  app.get<{ Params: { id: string } }>('/api/auth/cli/challenge/:id', rate, async (req) => {
    const c = challenges.get(req.params.id);
    if (!c || c.expires < Date.now()) {
      challenges.delete(req.params.id);
      return { status: 'expired' as const };
    }
    if (!c.token) return { status: 'pending' as const };
    const out = {
      status: 'ready' as const,
      token: c.token,
      tokenId: c.tokenId,
      username: c.username,
    };
    challenges.delete(req.params.id); // collected once
    return out;
  });
}
