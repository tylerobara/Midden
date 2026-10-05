import { describe, expect, it, vi } from 'vitest';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { main, parseConfig, pickCase, pollScan, uploadScan } from './midden-nmap.mjs';

const env = {
  MIDDEN_URL: 'https://midden.test/',
  MIDDEN_API_KEY: 'mk_test',
  MIDDEN_CASE_ID: 'case_1',
};

const scanFile = (): string => {
  const f = join(mkdtempSync(join(tmpdir(), 'mn-')), 'lab.xml');
  writeFileSync(f, '<nmaprun/');
  return f;
};

describe('parseConfig', () => {
  it('takes env, flags win, trailing slash trimmed', () => {
    const cfg = parseConfig(
      ['--case', 'case_2', '--phase', 'service', '-f', scanFile(), '-sT'],
      env,
    );
    expect(cfg).toMatchObject({
      url: 'https://midden.test',
      key: 'mk_test',
      caseId: 'case_2',
      phase: 'service',
      nmap: ['-sT'],
    });
  });
  it('lists every missing piece and rejects junk', () => {
    expect(() => parseConfig(['-f', scanFile()], {})).toThrow(
      /MIDDEN_URL.*MIDDEN_API_KEY(?!.*MIDDEN_CASE_ID)/,
    );
    expect(parseConfig(['--help'], {})).toMatchObject({ help: true });
    expect(() => parseConfig(['--phase', 'bogus', '-f', scanFile()], env)).toThrow(/--phase/);
    expect(() => parseConfig(['-f', '/nope.xml'], env)).toThrow(/no such file/);
    expect(() => parseConfig([], env)).toThrow(/nmap args/);
  });
});

describe('uploadScan + pollScan', () => {
  it('posts multipart with bearer and returns the scan', async () => {
    const fetchImpl = vi.fn(async (url: string, init: Record<string, unknown>) => {
      expect(url).toBe('https://midden.test/api/cases/case_1/scans');
      expect(init.headers.authorization).toBe('Bearer mk_test');
      const form = init.body as FormData;
      expect(form.get('name')).toBe('edge');
      expect(form.get('phase')).toBe('discovery');
      expect((form.get('file') as File).name).toBe('lab.xml');
      return new Response(JSON.stringify({ scan: { id: 's1', status: 'parsing' } }), {
        status: 201,
      });
    });
    const cfg = parseConfig(['-f', scanFile(), '--name', 'edge', '--phase', 'discovery'], env);
    await expect(uploadScan(cfg, cfg.file, { fetchImpl })).resolves.toEqual({
      id: 's1',
      status: 'parsing',
    });
    expect(fetchImpl).toHaveBeenCalledOnce();
  });
  it('surfaces server errors', async () => {
    const fetchImpl = vi.fn(async () => new Response('case gone', { status: 404 }));
    const cfg = parseConfig(['-f', scanFile()], env);
    await expect(uploadScan(cfg, cfg.file, { fetchImpl })).rejects.toThrow(/HTTP 404 case gone/);
  });
  it('polls until ready and reports failures', async () => {
    const seq = ['parsing', 'parsing', 'failed'];
    let n = 0;
    const fetchImpl = vi.fn(async () =>
      Response.json({
        scans: [
          {
            id: 's1',
            status: seq[Math.min(n++, 2)] ?? 'ready',
            error: n === 2 ? 'bad xml' : undefined,
          },
        ],
      }),
    );
    const cfg = parseConfig(['-f', scanFile()], env);
    await expect(
      pollScan(cfg, 's1', { fetchImpl }, { intervalMs: 1, timeoutMs: 2000 }),
    ).resolves.toMatchObject({ status: 'failed' });
    n = 0;
    await expect(
      pollScan(cfg, 'missing', { fetchImpl }, { intervalMs: 1, timeoutMs: 100 }),
    ).rejects.toThrow(/not found/);
  });
});

describe('case picker', () => {
  const listFetch = (cases: unknown[]) => vi.fn(async () => Response.json({ cases }));

  it('picks by number, re-prompts on junk', async () => {
    const cfg = { ...env, caseId: '' };
    const fetchImpl = listFetch([
      { id: 'case_a', number: 'CASE-1', name: 'first' },
      { id: 'case_b', number: 'CASE-2', name: 'second', archivedAt: 'yes' },
    ]);
    const prompt = vi.fn(async () => (prompt.mock.calls.length === 1 ? '9' : '2'));
    await expect(pickCase(cfg, { fetchImpl, prompt })).resolves.toBe('case_b');
    expect(prompt).toHaveBeenCalledTimes(2);
  });
  it('errors on an empty list', async () => {
    await expect(
      pickCase({ ...env, caseId: '' }, { fetchImpl: listFetch([]), prompt: async () => '1' }),
    ).rejects.toThrow(/no cases/);
  });
  it('main without a case id asks, then uploads to the pick', async () => {
    const fetchImpl = vi.fn(async (url: string, init?: { method?: string }) =>
      init?.method === 'POST'
        ? Response.json({ scan: { id: 's1', status: 'ready' } })
        : Response.json({ cases: [{ id: 'case_picked', number: 'C1', name: 'x' }] }),
    );
    const spawnImpl = vi.fn((_c: string, args: string[]) => {
      writeFileSync(args[1], '<nmaprun/>');
      return { status: 0 };
    });
    const prompt = vi.fn(async () => '1');
    const code = await main(
      ['10.0.0.0/24'],
      { ...env, MIDDEN_CASE_ID: '' },
      { fetchImpl, spawnImpl, prompt },
    );
    expect(code).toBe(0);
    expect(String(fetchImpl.mock.calls.find(([, i]) => i?.method === 'POST')[0])).toContain(
      'case_picked',
    );
  });
  it('refuses to hang without a terminal', async () => {
    const fetchImpl = vi.fn();
    expect(
      await main(
        ['x'],
        { ...env, MIDDEN_CASE_ID: '' },
        { fetchImpl, spawnImpl: () => ({ status: 0 }) },
      ),
    ).toBe(1);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

describe('main', () => {
  it('runs nmap, uploads, keeps exit 0', async () => {
    const fetchImpl = vi.fn(async () => Response.json({ scan: { id: 's1', status: 'ready' } }));
    const spawnImpl = vi.fn((_cmd: string, args: string[]) => {
      writeFileSync(args[1], '<nmaprun/>');
      return { status: 0 };
    });
    const code = await main(['10.0.0.0/24'], env, { fetchImpl, spawnImpl });
    expect(code).toBe(0);
    expect(spawnImpl.mock.calls[0][1][0]).toBe('-oX');
    expect(fetchImpl).toHaveBeenCalledOnce();
  });
  it('skips the upload when nmap dies', async () => {
    const fetchImpl = vi.fn();
    const spawnImpl = vi.fn(() => ({ status: 2 }));
    expect(await main(['-sS', 'x'], env, { fetchImpl, spawnImpl })).toBe(2);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
  it('exits 4 when a waited scan failed to parse', async () => {
    const fetchImpl = vi.fn(async (url: string, init?: { method?: string }) =>
      init?.method === 'POST'
        ? Response.json({ scan: { id: 's1', status: 'parsing' } })
        : Response.json({ scans: [{ id: 's1', status: 'failed', error: 'bad' }] }),
    );
    const spawnImpl = vi.fn((_cmd: string, args: string[]) => {
      writeFileSync(args[1], '<nmaprun/>');
      return { status: 0 };
    });
    expect(await main(['--wait', 'x'], env, { fetchImpl, spawnImpl })).toBe(4);
  });
});
