import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { readFileSync } from 'node:fs';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { synthNmapXmlString } from '@midden/core';
import { addUser, as, login, testAppWith } from '../test/helpers.js';
import { createApiToken } from '../auth/tokens.js';

const fixture = (name: string): Buffer =>
  readFileSync(new URL(`../../../core/fixtures/nmap/${name}`, import.meta.url));

function multipart(
  fields: Record<string, string>,
  file: { name: string; content: Buffer | string; mime?: string },
): { payload: Buffer; headers: Record<string, string> } {
  const boundary = '----midden' + Math.random().toString(36).slice(2);
  const parts: Buffer[] = [];
  for (const [k, v] of Object.entries(fields))
    parts.push(
      Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`),
    );
  parts.push(
    Buffer.from(
      `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${file.name}"\r\nContent-Type: ${file.mime ?? 'application/octet-stream'}\r\n\r\n`,
    ),
  );
  parts.push(Buffer.isBuffer(file.content) ? file.content : Buffer.from(file.content));
  parts.push(Buffer.from(`\r\n--${boundary}--\r\n`));
  return {
    payload: Buffer.concat(parts),
    headers: { 'content-type': `multipart/form-data; boundary=${boundary}` },
  };
}

async function waitReady(
  app: FastifyInstance,
  cookie: string,
  caseId: string,
  scanId: string,
): Promise<{ status: string; error: string; hostsUp: number }> {
  for (let i = 0; i < 100; i++) {
    await Promise.allSettled([...app.pendingIngests]);
    const st = await app.inject({
      method: 'GET',
      url: `/api/cases/${caseId}/state`,
      ...as(cookie),
    });
    const scan = st.json().state.scans[scanId];
    if (scan && scan.status !== 'parsing') return scan;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error('scan never finished');
}

describe('terrain routes', () => {
  let app: FastifyInstance;
  let ann: string;
  let annId: string;
  let vic: string;
  let caseId: string;
  beforeEach(async () => {
    app = testAppWith({
      MIDDEN_BLOB_DIR: mkdtempSync(join(tmpdir(), 'midden-blobs-')),
      MIDDEN_MAX_UPLOAD_MB: '64',
    });
    annId = addUser(app, 'ann');
    addUser(app, 'vic', 'viewer');
    await app.ready();
    ann = await login(app, 'ann');
    vic = await login(app, 'vic');
    const c = await app.inject({
      method: 'POST',
      url: '/api/cases',
      ...as(ann),
      payload: { name: 'Terrain' },
    });
    caseId = c.json().case.id as string;
  });
  afterEach(async () => {
    await app.close();
  });

  const upload = async (
    cookie: string,
    file: { name: string; content: Buffer | string },
    fields: Record<string, string> = {},
  ) => {
    const mp = multipart(fields, file);
    return app.inject({
      method: 'POST',
      url: `/api/cases/${caseId}/scans`,
      ...as(cookie, { headers: mp.headers }),
      payload: mp.payload,
    });
  };

  it('ingests an XML upload, lists it, pages hosts, aggregates the map, serves targets and raw, and deletes', async () => {
    const res = await upload(
      ann,
      { name: 'lab-small.xml', content: fixture('lab-small.xml') },
      { name: 'Lab discovery' },
    );
    expect(res.statusCode).toBe(201);
    const scanId = res.json().scan.id as string;
    expect(res.json().scan).toMatchObject({ status: 'parsing', fmt: 'xml', name: 'Lab discovery' });
    const ready = await waitReady(app, ann, caseId, scanId);
    expect(ready).toMatchObject({ status: 'ready', hostsUp: 6 });

    const list = await app.inject({ method: 'GET', url: `/api/cases/${caseId}/scans`, ...as(vic) });
    expect(list.json().scans[0]).toMatchObject({
      id: scanId,
      hostCount: 6,
      phase: 'service',
      nmapVersion: '7.98',
      uploadedBy: annId,
      uploadedByName: 'ANN',
    });

    const page1 = await app.inject({
      method: 'GET',
      url: `/api/cases/${caseId}/scans/${scanId}/hosts?limit=4`,
      ...as(vic),
    });
    expect(page1.json().items.map((h: { ip: string }) => h.ip)).toEqual([
      '10.20.0.1',
      '10.20.1.5',
      '10.20.4.31',
      '10.20.4.77',
    ]);
    expect(page1.json().next).toBeTruthy();
    const page2 = await app.inject({
      method: 'GET',
      url: `/api/cases/${caseId}/scans/${scanId}/hosts?limit=4&after=${page1.json().next}`,
      ...as(vic),
    });
    expect(page2.json().items.map((h: { ip: string }) => h.ip)).toEqual([
      '10.20.9.100',
      '2001:db8:1::10',
    ]);
    expect(page2.json().next).toBeNull();
    expect(page1.json().items[1]).toMatchObject({
      role: 'Domain controller',
      bucket: 'Windows',
      openCount: 9,
    });
    expect(page1.json().items[1].ports).toHaveLength(9);

    const f = async (qs: string): Promise<string[]> =>
      (
        await app.inject({
          method: 'GET',
          url: `/api/cases/${caseId}/scans/${scanId}/hosts?${qs}`,
          ...as(vic),
        })
      )
        .json()
        .items.map((h: { ip: string }) => h.ip);
    expect(await f('port=445')).toEqual(['10.20.1.5', '10.20.4.77']);
    expect(await f('net=10.20.4.0/24')).toEqual(['10.20.4.31', '10.20.4.77']);
    expect(await f('bucket=Printer')).toEqual(['10.20.9.100']);
    expect(await f('flagged=1')).toEqual(['10.20.0.1', '10.20.1.5', '10.20.4.77']);
    expect(await f('q=nginx')).toEqual(['10.20.4.31']);
    expect(await f('q=corp.example')).toHaveLength(5);

    const detail = await app.inject({
      method: 'GET',
      url: `/api/cases/${caseId}/scans/${scanId}/hosts/10.20.4.31`,
      ...as(vic),
    });
    expect(detail.json().host.ports[0]).toMatchObject({
      port: 22,
      product: 'OpenSSH',
      cpe: ['cpe:/a:openbsd:openssh:9.2p1', 'cpe:/o:linux:linux_kernel'],
    });
    expect(detail.json().host.trace).toHaveLength(3);
    expect(detail.json().host.scripts).toEqual([]);
    expect(
      (
        await app.inject({
          method: 'GET',
          url: `/api/cases/${caseId}/scans/${scanId}/hosts/1.2.3.4`,
          ...as(vic),
        })
      ).statusCode,
    ).toBe(404);

    const map = await app.inject({
      method: 'GET',
      url: `/api/cases/${caseId}/scans/${scanId}/map`,
      ...as(vic),
    });
    const nets = map.json().nets as Array<{
      netKey: string;
      hosts: number;
      flagged: number;
      buckets: Record<string, number>;
    }>;
    expect(nets.map((n) => n.netKey)).toEqual([
      '10.20.0.0/24',
      '10.20.1.0/24',
      '10.20.4.0/24',
      '10.20.9.0/24',
      '2001:db8:1::/64',
    ]);
    expect(nets[2]).toMatchObject({
      hosts: 2,
      flagged: 1,
      buckets: { 'Linux / Unix': 1, Windows: 1 },
    });
    const map16 = await app.inject({
      method: 'GET',
      url: `/api/cases/${caseId}/scans/${scanId}/map?bits=16`,
      ...as(vic),
    });
    expect(
      map16.json().nets.map((n: { netKey: string; hosts: number }) => [n.netKey, n.hosts]),
    ).toEqual([
      ['10.20.0.0/16', 5],
      ['2001:db8:1::/64', 1],
    ]);
    const net = await app.inject({
      method: 'GET',
      url: `/api/cases/${caseId}/scans/${scanId}/map?net=10.20.4.0/24`,
      ...as(vic),
    });
    expect(net.json().hosts.map((h: { ip: string }) => h.ip)).toEqual(['10.20.4.31', '10.20.4.77']);
    const trace = await app.inject({
      method: 'GET',
      url: `/api/cases/${caseId}/scans/${scanId}/map?layout=trace`,
      ...as(vic),
    });
    expect(
      trace.json().hosts.map((h: { ip: string; trace: unknown[] }) => [h.ip, h.trace.length]),
    ).toEqual([
      ['10.20.1.5', 2],
      ['10.20.4.31', 3],
    ]);

    const targets = await app.inject({
      method: 'GET',
      url: `/api/cases/${caseId}/scans/${scanId}/targets.txt`,
      ...as(vic),
    });
    expect(targets.body).toBe(
      '10.20.0.1\n10.20.1.5\n10.20.4.31\n10.20.4.77\n10.20.9.100\n2001:db8:1::10\n',
    );
    const raw = await app.inject({
      method: 'GET',
      url: `/api/cases/${caseId}/scans/${scanId}/raw`,
      ...as(vic),
    });
    expect(raw.rawPayload.length).toBe(fixture('lab-small.xml').length);

    expect(
      (
        await app.inject({
          method: 'DELETE',
          url: `/api/cases/${caseId}/scans/${scanId}`,
          ...as(vic),
        })
      ).statusCode,
    ).toBe(403);
    expect(
      (
        await app.inject({
          method: 'DELETE',
          url: `/api/cases/${caseId}/scans/${scanId}`,
          ...as(ann),
        })
      ).statusCode,
    ).toBe(200);
    expect(
      (await app.inject({ method: 'GET', url: `/api/cases/${caseId}/scans`, ...as(ann) })).json()
        .scans,
    ).toEqual([]);
    expect(app.db.get('SELECT COUNT(*) AS n FROM scan_hosts')).toEqual({ n: 0 });
    expect(app.db.get('SELECT COUNT(*) AS n FROM blobs')).toEqual({ n: 0 });
    const st = await app.inject({ method: 'GET', url: `/api/cases/${caseId}/state`, ...as(ann) });
    expect(st.json().state.scans).toEqual({});
  });

  it('attributes bearer (CLI) uploads to the API key owner', async () => {
    const { key } = createApiToken(app.db, annId, 'midden CLI');
    const mp = multipart(
      { name: 'edge sweep' },
      { name: 'edge.xml', content: fixture('lab-small.xml') },
    );
    const res = await app.inject({
      method: 'POST',
      url: `/api/cases/${caseId}/scans`,
      headers: { authorization: `Bearer ${key}`, 'content-type': mp.headers['content-type'] },
      payload: mp.payload,
    });
    expect(res.statusCode).toBe(201);
    const list = await app.inject({ method: 'GET', url: `/api/cases/${caseId}/scans`, ...as(ann) });
    expect(list.json().scans).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'edge sweep', uploadedBy: annId, uploadedByName: 'ANN' }),
      ]),
    );
  });

  it('accepts -oN text, infers the phase, and shares one blob between identical uploads', async () => {
    const a = await upload(ann, { name: 'a.nmap', content: fixture('lab-small.nmap') });
    const b = await upload(
      ann,
      { name: 'b.nmap', content: fixture('lab-small.nmap') },
      { phase: 'discovery' },
    );
    const ra = await waitReady(app, ann, caseId, a.json().scan.id);
    const rb = await waitReady(app, ann, caseId, b.json().scan.id);
    expect(ra).toMatchObject({ status: 'ready', hostsUp: 5 });
    expect(rb.status).toBe('ready');
    const list = (
      await app.inject({ method: 'GET', url: `/api/cases/${caseId}/scans`, ...as(ann) })
    ).json().scans as Array<{ id: string; phase: string; fmt: string; hostCount: number }>;
    expect(list.find((s) => s.id === a.json().scan.id)).toMatchObject({
      fmt: 'text',
      phase: 'service',
      hostCount: 4,
    });
    expect(list.find((s) => s.id === b.json().scan.id)).toMatchObject({ phase: 'discovery' });
    expect(app.db.get('SELECT refcount FROM blobs')).toEqual({ refcount: 2 });
    await app.inject({
      method: 'DELETE',
      url: `/api/cases/${caseId}/scans/${a.json().scan.id}`,
      ...as(ann),
    });
    expect(app.db.get('SELECT refcount FROM blobs')).toEqual({ refcount: 1 });
  });

  it('rejects viewers, unknown formats, empty and oversized files', async () => {
    expect(
      (await upload(vic, { name: 'x.xml', content: fixture('lab-small.xml') })).statusCode,
    ).toBe(403);
    const junk = await upload(ann, { name: 'x.json', content: '{"hosts":[]}' });
    expect(junk.statusCode).toBe(400);
    expect(junk.json().error.message).toMatch(/Not recognised/);
    expect((await upload(ann, { name: 'empty.xml', content: '' })).statusCode).toBe(400);
    expect(app.db.get('SELECT COUNT(*) AS n FROM blobs')).toEqual({ n: 0 });
    expect(app.db.get('SELECT COUNT(*) AS n FROM scans')).toEqual({ n: 0 });

    // A dedicated 1 MB server so the cap can be exceeded without a huge fixture.
    const small = testAppWith({
      MIDDEN_BLOB_DIR: mkdtempSync(join(tmpdir(), 'midden-blobs-small-')),
      MIDDEN_MAX_UPLOAD_MB: '1',
    });
    addUser(small, 'ann');
    await small.ready();
    const smallCookie = await login(small, 'ann');
    const smallCase = (
      await small.inject({
        method: 'POST',
        url: '/api/cases',
        ...as(smallCookie),
        payload: { name: 'Small' },
      })
    ).json().case.id as string;
    const mp = multipart(
      {},
      {
        name: 'big.xml',
        content: Buffer.concat([
          Buffer.from('<?xml version="1.0"?><nmaprun>'),
          Buffer.alloc(1_100_000, 'x'),
        ]),
      },
    );
    const res = await small.inject({
      method: 'POST',
      url: `/api/cases/${smallCase}/scans`,
      ...as(smallCookie, { headers: mp.headers }),
      payload: mp.payload,
    });
    expect(res.statusCode).toBe(413);
    expect(small.db.get('SELECT COUNT(*) AS n FROM blobs')).toEqual({ n: 0 });
    expect(small.db.get('SELECT COUNT(*) AS n FROM scans')).toEqual({ n: 0 });
    await small.close();
  });

  it('marks a scan failed when the XML is broken, without losing the case', async () => {
    const res = await upload(ann, {
      name: 'broken.xml',
      content:
        '<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>',
    });
    expect(res.statusCode).toBe(201);
    const r = await waitReady(app, ann, caseId, res.json().scan.id);
    expect(r.status).toBe('failed');
    expect(r.error).toMatch(/parse/i);
  });

  it('ingests a synthetic /16 quickly', async () => {
    const xml = synthNmapXmlString({ hosts: 8192, portsPerHost: 4, seed: 3 });
    const t0 = Date.now();
    const res = await upload(ann, { name: 'synth.xml', content: xml });
    expect(res.statusCode).toBe(201);
    const r = await waitReady(app, ann, caseId, res.json().scan.id);
    expect(r).toMatchObject({ status: 'ready', hostsUp: 8192 });
    expect(Date.now() - t0).toBeLessThan(20_000);
    const map = await app.inject({
      method: 'GET',
      url: `/api/cases/${caseId}/scans/${res.json().scan.id}/map`,
      ...as(ann),
    });
    expect(map.json().nets).toHaveLength(33);
  }, 60_000);
});
