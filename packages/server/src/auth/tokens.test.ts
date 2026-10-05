import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { addUser, as, login, testAppWith } from '../test/helpers.js';
import { MAX_TOKENS_PER_USER } from './tokens.js';

const fixture = (): Buffer =>
  readFileSync(new URL('../../../core/fixtures/nmap/lab-small.xml', import.meta.url));

function multipart(file: { name: string; content: Buffer }): {
  payload: Buffer;
  headers: Record<string, string>;
} {
  const boundary = '----midden' + Math.random().toString(36).slice(2);
  return {
    payload: Buffer.concat([
      Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${file.name}"\r\nContent-Type: application/octet-stream\r\n\r\n`,
      ),
      file.content,
      Buffer.from(`\r\n--${boundary}--\r\n`),
    ]),
    headers: { 'content-type': `multipart/form-data; boundary=${boundary}` },
  };
}

describe('api tokens', () => {
  let app: FastifyInstance;
  let ann: string;
  let caseId: string;

  beforeEach(async () => {
    app = testAppWith({
      MIDDEN_BLOB_DIR: mkdtempSync(join(tmpdir(), 'midden-blobs-')),
      MIDDEN_MAX_UPLOAD_MB: '64',
    });
    addUser(app, 'ann');
    await app.ready();
    ann = await login(app, 'ann');
    const c = await app.inject({
      method: 'POST',
      url: '/api/cases',
      ...as(ann),
      payload: { name: 'K' },
    });
    caseId = c.json().case.id as string;
  });
  afterEach(async () => {
    await app.close();
  });

  const createKey = async (name = 'nmap plugin'): Promise<{ id: string; key: string }> => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/auth/tokens',
      ...as(ann),
      payload: { name },
    });
    expect(res.statusCode).toBe(201);
    return res.json();
  };

  it('bearer key uploads a scan without the CSRF header or cookie', async () => {
    const { key } = await createKey();
    const mp = multipart({ name: 'lab.xml', content: fixture() });
    const up = await app.inject({
      method: 'POST',
      url: `/api/cases/${caseId}/scans`,
      headers: { authorization: `Bearer ${key}`, ...mp.headers },
      payload: mp.payload,
    });
    expect(up.statusCode).toBe(201);
    await Promise.allSettled([...app.pendingIngests]);
    const list = await app.inject({
      method: 'GET',
      url: `/api/cases/${caseId}/scans`,
      headers: { authorization: `Bearer ${key}` },
    });
    expect(list.json().scans).toHaveLength(1);
  });

  it('rejects a bad key and still guards cookie POSTs with the CSRF header', async () => {
    const bad = await app.inject({
      method: 'GET',
      url: '/api/auth/me',
      headers: { authorization: 'Bearer mk_nope' },
    });
    expect(bad.statusCode).toBe(401);
    expect(bad.json().error.code).toBe('unauthorized');
    // Same session cookie as the working key create, but without x-midden-client.
    const noCsrf = await app.inject({
      method: 'POST',
      url: '/api/auth/tokens',
      headers: { cookie: ann, 'content-type': 'application/json' },
      payload: { name: 'x' },
    });
    expect(noCsrf.statusCode).toBe(403);
    expect(noCsrf.json().error.code).toBe('csrf');
  });

  it('revoke kills the key; ids are scoped to their owner', async () => {
    const { id, key } = await createKey();
    addUser(app, 'bob');
    const other = await login(app, 'bob');
    const notYours = await app.inject({
      method: 'DELETE',
      url: `/api/auth/tokens/${id}`,
      ...as(other),
    });
    expect(notYours.statusCode).toBe(404);
    const mine = await app.inject({ method: 'DELETE', url: `/api/auth/tokens/${id}`, ...as(ann) });
    expect(mine.statusCode).toBe(200);
    const after = await app.inject({
      method: 'GET',
      url: '/api/auth/me',
      headers: { authorization: `Bearer ${key}` },
    });
    expect(after.statusCode).toBe(401);
  });

  it('lists metadata only and caps keys per user', async () => {
    for (let i = 0; i < MAX_TOKENS_PER_USER; i++) await createKey(`k${i}`);
    const list = await app.inject({ method: 'GET', url: '/api/auth/tokens', ...as(ann) });
    expect(list.json().tokens[0]).not.toHaveProperty('key');
    expect(list.json().tokens[0]).not.toHaveProperty('token_hash');
    expect(list.json().tokens).toHaveLength(MAX_TOKENS_PER_USER);
    const over = await app.inject({
      method: 'POST',
      url: '/api/auth/tokens',
      ...as(ann),
      payload: { name: 'one too many' },
    });
    expect(over.statusCode).toBe(409);
    expect(over.json().error.code).toBe('too_many_tokens');
  });
});
