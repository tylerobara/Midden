import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { addUser, as, login, testApp } from '../test/helpers.js';

describe('cli login handshake', () => {
  let app: FastifyInstance;
  let ann: string;

  beforeEach(async () => {
    app = testApp();
    addUser(app, 'ann');
    await app.ready();
    ann = await login(app, 'ann');
  });
  afterEach(async () => {
    await app.close();
  });

  const challenge = async (): Promise<string> => {
    const res = await app.inject({ method: 'GET', url: '/api/auth/cli/challenge' });
    expect(res.statusCode).toBe(200);
    expect(res.json().challenge).toMatch(/^[a-f0-9]{32}$/);
    return res.json().challenge;
  };
  const poll = async (id: string) =>
    (await app.inject({ method: 'GET', url: `/api/auth/cli/challenge/${id}` })).json();

  it('full handshake: challenge -> browser authorize -> CLI collects one token', async () => {
    const id = await challenge();
    expect((await poll(id)).status).toBe('pending');
    const auth = await app.inject({
      method: 'POST',
      url: '/api/auth/cli/authorize',
      ...as(ann),
      payload: { challenge: id },
    });
    expect(auth.statusCode).toBe(200);
    expect(auth.json().username).toBe('ann');
    const ready = await poll(id);
    expect(ready).toMatchObject({ status: 'ready', username: 'ann' });
    expect(ready.token).toMatch(/^mk_/);
    // token works
    const me = await app.inject({
      method: 'GET',
      url: '/api/auth/me',
      headers: { authorization: `Bearer ${ready.token}` },
    });
    expect(me.json().user.username).toBe('ann');
    // collected once
    expect((await poll(id)).status).toBe('expired');
  });

  it('authorize needs a session and rejects reuse or junk', async () => {
    // CSRF header supplied with a junk cookie: gets past the CSRF guard so
    // requireUser is the thing that rejects it.
    const anon = await app.inject({
      method: 'POST',
      url: '/api/auth/cli/authorize',
      ...as('sid=nope'),
      payload: { challenge: 'a'.repeat(32) },
    });
    expect(anon.statusCode).toBe(401);
    const noCsrf = await app.inject({
      method: 'POST',
      url: '/api/auth/cli/authorize',
      payload: { challenge: 'a'.repeat(32) },
    });
    expect(noCsrf.statusCode).toBe(403);
    const id = await challenge();
    const ok = { method: 'POST' as const, url: '/api/auth/cli/authorize', ...as(ann) };
    expect((await app.inject({ ...ok, payload: { challenge: id } })).statusCode).toBe(200);
    expect((await app.inject({ ...ok, payload: { challenge: id } })).json().error.code).toBe(
      'bad_challenge',
    );
    expect((await app.inject({ ...ok, payload: { challenge: 'zz' } })).statusCode).toBe(400);
  });

  it('unknown or stale challenges come back expired', async () => {
    expect((await poll('f'.repeat(32))).status).toBe('expired');
  });
});
