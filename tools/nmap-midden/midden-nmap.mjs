#!/usr/bin/env node
/**
 * midden-nmap — run nmap and upload the result to a Midden case, or upload an
 * existing -oX/-oN file. Configure with env vars (flags win):
 *
 *   MIDDEN_URL=https://midden.corp.example MIDDEN_API_KEY=mk_... MIDDEN_CASE_ID=case_...
 *   midden-nmap -sT -T4 10.0.0.0/24                 # scan + upload
 *   midden-nmap -f scan.xml --name "edge sweep" --phase discovery --wait
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { pathToFileURL } from 'node:url';

const PHASES = ['discovery', 'service', 'other'];

export function parseConfig(argv, env) {
  const cfg = {
    url: env.MIDDEN_URL ?? '',
    key: env.MIDDEN_API_KEY ?? '',
    caseId: env.MIDDEN_CASE_ID ?? '',
    name: '',
    phase: '',
    file: '',
    keep: false,
    wait: false,
    nmap: [],
  };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`missing value for ${a}`);
      return v;
    };
    if (a === '--url') cfg.url = next();
    else if (a === '--key') cfg.key = next();
    else if (a === '--case') cfg.caseId = next();
    else if (a === '--name') cfg.name = next();
    else if (a === '--phase') cfg.phase = next();
    else if (a === '-f' || a === '--file') cfg.file = next();
    else if (a === '--keep') cfg.keep = true;
    else if (a === '--wait') cfg.wait = true;
    else if (a === '-h' || a === '--help') cfg.help = true;
    else rest.push(a);
  }
  cfg.nmap = rest;
  cfg.url = cfg.url.replace(/\/+$/, '');
  if (cfg.help) return cfg;
  const missing = [
    !cfg.url && 'MIDDEN_URL (or --url)',
    !cfg.key && 'MIDDEN_API_KEY (or --key)',
    cfg.phase && !PHASES.includes(cfg.phase) ? `--phase must be one of ${PHASES.join(', ')}` : '',
    cfg.file && !existsSync(cfg.file) ? `no such file: ${cfg.file}` : '',
    !cfg.file && !cfg.nmap.length && 'give nmap args or -f <scan file>',
  ].filter(Boolean);
  if (missing.length) throw new Error(`config error: ${missing.join('; ')}`);
  return cfg;
}

/** Numbered case picker (used when MIDDEN_CASE_ID is unset). prompt is injectable for tests. */
export async function pickCase(cfg, deps) {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const res = await fetchImpl(`${cfg.url}/api/cases`, {
    headers: { authorization: `Bearer ${cfg.key}` },
  });
  if (!res.ok) throw new Error(`case list failed: HTTP ${res.status}`);
  const cases = (await res.json()).cases;
  if (!cases.length) throw new Error('no cases to upload to — create one in the web UI first');
  console.log('cases:');
  cases.forEach((c, i) =>
    console.log(`> ${i + 1}) ${c.number} — ${c.name}${c.archivedAt ? ' [archived]' : ''}`),
  );
  let prompt = deps.prompt;
  if (!prompt) {
    const rl = (await import('node:readline/promises')).default.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    prompt = (q) => rl.question(q).finally(() => rl.close());
  }
  for (;;) {
    const n = Number((await prompt('type the case number you want to upload results to: ')).trim());
    if (Number.isInteger(n) && n >= 1 && n <= cases.length) return cases[n - 1].id;
    console.log(`not a case number (1-${cases.length})`);
  }
}

export async function uploadScan(cfg, filePath, deps) {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const form = new FormData();
  const bytes = readFileSync(filePath);
  form.append('file', new Blob([bytes]), basename(filePath));
  form.append('name', cfg.name || basename(filePath));
  if (cfg.phase) form.append('phase', cfg.phase);
  const res = await fetchImpl(`${cfg.url}/api/cases/${cfg.caseId}/scans`, {
    method: 'POST',
    headers: { authorization: `Bearer ${cfg.key}` },
    body: form,
  });
  if (!res.ok)
    throw new Error(`upload failed: HTTP ${res.status} ${(await res.text()).slice(0, 200)}`);
  return (await res.json()).scan;
}

export async function pollScan(
  cfg,
  scanId,
  deps,
  { timeoutMs = 300_000, intervalMs = 2_000 } = {},
) {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const res = await fetchImpl(`${cfg.url}/api/cases/${cfg.caseId}/scans`, {
      headers: { authorization: `Bearer ${cfg.key}` },
    });
    if (!res.ok) throw new Error(`poll failed: HTTP ${res.status}`);
    const scan = (await res.json()).scans.find((s) => s.id === scanId);
    if (!scan) throw new Error(`scan ${scanId} not found`);
    if (scan.status !== 'parsing') return scan;
    if (Date.now() > deadline)
      throw new Error(`scan ${scanId} still parsing after ${timeoutMs / 1000}s`);
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

export async function main(argv, env, deps = {}) {
  let cfg;
  try {
    cfg = parseConfig(argv, env);
  } catch (err) {
    console.error(String(err.message));
    return 1;
  }
  if (cfg.help) {
    console.error(
      'usage: midden-nmap [--name n] [--phase discovery|service|other] [--keep] [--wait]\n' +
        '         [nmap args...]            run nmap and upload its XML\n' +
        '       midden-nmap -f scan.xml [same options]   upload an existing file\n' +
        'env: MIDDEN_URL, MIDDEN_API_KEY, MIDDEN_CASE_ID (flags --url --key --case win)\n' +
        'without MIDDEN_CASE_ID the tool lists your cases and asks you to pick one',
    );
    return 0;
  }
  if (!cfg.caseId) {
    if (!deps.prompt && !process.stdin.isTTY) {
      console.error('config error: MIDDEN_CASE_ID (or --case); no terminal to pick interactively');
      return 1;
    }
    try {
      cfg.caseId = await pickCase(cfg, deps);
    } catch (err) {
      console.error(String(err.message ?? err));
      return 1;
    }
  }
  const tmp = cfg.file ? '' : mkdtempSync(join(tmpdir(), 'midden-nmap-'));
  const file = cfg.file || (tmp && join(tmp, 'scan.xml'));
  try {
    if (!cfg.file) {
      const run = (deps.spawnImpl ?? spawnSync)('nmap', ['-oX', file, ...cfg.nmap], {
        stdio: 'inherit',
      });
      if (run.status !== 0 && run.status !== 1) {
        console.error(`nmap exited ${run.status}; upload skipped`);
        return run.status ?? 2;
      }
      if (!existsSync(file)) {
        console.error('nmap produced no XML; upload skipped');
        return 2;
      }
    }
    const scan = await uploadScan(cfg, file, deps);
    const link = `${cfg.url}/#/c/${cfg.caseId}/scans`;
    let final = scan;
    if (cfg.wait) final = await pollScan(cfg, scan.id, deps);
    if (final.status === 'failed') {
      console.error(`scan ${scan.id} failed to parse: ${final.error ?? 'unknown error'}`);
      console.error(link);
      return 4;
    }
    console.log(
      `scan ${scan.id} uploaded${cfg.wait ? ` (${final.status})` : ' (parsing)'} → ${link}`,
    );
    if (cfg.keep && !cfg.file && tmp) {
      const keep = join(process.cwd(), basename(file));
      rmSync(keep, { force: true });
      spawnSync('cp', [file, keep]);
      console.log(`kept ${keep}`);
    }
    return 0;
  } catch (err) {
    console.error(String(err.message ?? err));
    return 3;
  } finally {
    if (tmp && !cfg.keep) rmSync(tmp, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  process.exitCode = await main(process.argv.slice(2), process.env);
