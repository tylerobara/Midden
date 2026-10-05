/**
 * Terrain API: scan upload and ingestion, paged host listing, subnet aggregates, trace data,
 * target lists, raw download and removal. Pure terrain only: the client overlays case status
 * from its own state by IP, so a status change never needs a refetch.
 */
import { open } from 'node:fs/promises';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  aggregateByNet,
  compareIps,
  detectNmapFormat,
  inferPhase,
  ScanFormatSchema,
  ScanPhaseSchema,
  type Hop,
  type TerrainHostSummary,
  type NetAggregate,
  type Op,
  type ScanFormat,
  type ScanHost,
  type ScanMeta,
  type ScriptOutput,
} from '@midden/core';
import { accessOrThrow } from '../cases/routes.js';
import { HttpError, badRequest, notFound } from '../lib/errors.js';
import { newId, nowIso } from '../lib/ids.js';
import { TooLargeError } from '../blobs/store.js';
import { ingestScan } from './ingest.js';
import { deleteScanRows } from './insert.js';

const HostsQuery = z.object({
  after: z.string().max(64).optional(),
  limit: z.coerce.number().int().min(1).max(1000).default(200),
  net: z.string().max(64).optional(),
  port: z.coerce.number().int().min(0).max(65535).optional(),
  bucket: z.string().max(64).optional(),
  q: z.string().max(200).optional(),
  flagged: z.enum(['0', '1']).optional(),
});
const MapQuery = z.object({
  layout: z.enum(['subnet', 'trace']).default('subnet'),
  bits: z.coerce.number().int().min(8).max(32).default(24),
  net: z.string().max(64).optional(),
});

interface ScanRow {
  id: string;
  case_id: string;
  name: string;
  phase: ScanMeta['phase'];
  fmt: ScanFormat;
  nmap_args: string;
  nmap_version: string;
  started_at: string;
  finished_at: string;
  elapsed_s: number | null;
  hosts_up: number;
  hosts_down: number;
  hosts_total: number;
  raw_sha256: string;
  uploaded_by: string;
  uploaded_by_name: string;
  uploaded_at: string;
  status: ScanMeta['status'];
  error: string;
}

interface HostRow {
  id: number;
  ip: string;
  ip_sort: string;
  net_key: string;
  ipv6: string;
  mac: string;
  vendor: string;
  hostnames: string;
  state: string;
  reason: string;
  latency: string;
  distance: number | null;
  uptime: string;
  os_name: string;
  os_accuracy: string;
  os_family: string;
  os_vendor: string;
  os_type: string;
  bucket: string;
  role: string;
  flags: string;
  open_count: number;
}

export function scanRowToMeta(r: ScanRow): ScanMeta {
  return {
    id: r.id,
    name: r.name,
    phase: r.phase,
    fmt: r.fmt,
    args: r.nmap_args,
    nmapVersion: r.nmap_version,
    startedAt: r.started_at,
    finishedAt: r.finished_at,
    elapsedS: r.elapsed_s === null ? null : Number(r.elapsed_s),
    hostsUp: Number(r.hosts_up),
    hostsDown: Number(r.hosts_down),
    hostsTotal: Number(r.hosts_total),
    rawSha256: r.raw_sha256,
    uploadedBy: r.uploaded_by,
    uploadedByName: r.uploaded_by_name,
    uploadedAt: r.uploaded_at,
    status: r.status,
    error: r.error,
  };
}

function rowToSummary(app: FastifyInstance, r: HostRow): TerrainHostSummary {
  const ports = app.db.all<{ port: number; proto: string; name: string }>(
    'SELECT port, proto, name FROM scan_ports WHERE scan_host_id = ? ORDER BY proto, port',
    r.id,
  );
  return {
    ip: r.ip,
    ipv6: r.ipv6,
    mac: r.mac,
    vendor: r.vendor,
    hostnames: JSON.parse(r.hostnames) as string[],
    state: r.state,
    reason: r.reason,
    latency: r.latency,
    distance: r.distance === null ? null : Number(r.distance),
    uptime: r.uptime,
    osName: r.os_name,
    osAccuracy: r.os_accuracy,
    osFamily: r.os_family,
    osVendor: r.os_vendor,
    osType: r.os_type,
    bucket: r.bucket,
    role: r.role,
    flags: JSON.parse(r.flags) as string[],
    openCount: Number(r.open_count),
    ports: ports.map((p) => ({ port: Number(p.port), proto: p.proto, name: p.name })),
  };
}

function rowToFull(app: FastifyInstance, r: HostRow): ScanHost {
  const s = rowToSummary(app, r);
  const ports = app.db.all<{
    port: number;
    proto: string;
    state: string;
    name: string;
    product: string;
    version: string;
    extra: string;
    tunnel: string;
    cpe: string;
    scripts: string;
  }>('SELECT * FROM scan_ports WHERE scan_host_id = ? ORDER BY proto, port', r.id);
  const hops = app.db.all<{ ttl: number; ip: string; host: string; rtt: string }>(
    'SELECT ttl, ip, host, rtt FROM scan_hops WHERE scan_host_id = ? ORDER BY ttl',
    r.id,
  );
  const scripts = app.db.all<{ script_id: string; output: string }>(
    'SELECT script_id, output FROM scan_scripts WHERE scan_host_id = ?',
    r.id,
  );
  return {
    ...s,
    ports: ports.map((p) => ({
      port: Number(p.port),
      proto: p.proto,
      state: p.state,
      name: p.name,
      product: p.product,
      version: p.version,
      extra: p.extra,
      tunnel: p.tunnel,
      cpe: JSON.parse(p.cpe) as string[],
      scripts: JSON.parse(p.scripts) as ScriptOutput[],
    })),
    trace: hops.map((h): Hop => ({ ttl: Number(h.ttl), ip: h.ip, host: h.host, rtt: h.rtt })),
    scripts: scripts.map((x) => ({ id: x.script_id, output: x.output })),
  };
}

function loadScan(app: FastifyInstance, caseId: string, scanId: string): ScanRow {
  const r = app.db.get<ScanRow>('SELECT * FROM scans WHERE id = ? AND case_id = ?', scanId, caseId);
  if (!r) throw notFound('No such scan');
  return r;
}

export async function terrainRoutes(app: FastifyInstance): Promise<void> {
  app.get<{ Params: { id: string } }>('/api/cases/:id/scans', async (req) => {
    accessOrThrow(app, req, req.params.id, 'read');
    const rows = app.db.all<ScanRow & { host_count: number }>(
      'SELECT s.*, (SELECT COUNT(*) FROM scan_hosts sh WHERE sh.scan_id = s.id) AS host_count FROM scans s WHERE s.case_id = ? ORDER BY s.uploaded_at DESC',
      req.params.id,
    );
    return { scans: rows.map((r) => ({ ...scanRowToMeta(r), hostCount: Number(r.host_count) })) };
  });

  app.post<{ Params: { id: string } }>('/api/cases/:id/scans', async (req, reply) => {
    const { user, access } = accessOrThrow(app, req, req.params.id, 'edit');
    const caseId = req.params.id;
    const parts = req.parts({ limits: { fileSize: app.cfg.maxUploadMb * 1_048_576, files: 1 } });
    let stored: { sha256: string; size: number; path: string } | null = null;
    let fileName = 'scan';
    let name = '';
    let phase: string | undefined;
    for await (const part of parts) {
      if (part.type === 'file') {
        fileName = part.filename || fileName;
        try {
          stored = await app.blobs.putStream(part.file, {
            maxBytes: app.cfg.maxUploadMb * 1_048_576,
          });
        } catch (err) {
          if (err instanceof TooLargeError) throw new HttpError(413, err.message, 'too_large');
          throw err;
        }
        if (part.file.truncated) {
          await app.blobs.release(stored.sha256);
          throw new HttpError(
            413,
            `Upload exceeds the ${app.cfg.maxUploadMb} MB limit`,
            'too_large',
          );
        }
      } else if (part.fieldname === 'name') name = String(part.value).slice(0, 200);
      else if (part.fieldname === 'phase') phase = String(part.value);
    }
    if (!stored) throw badRequest('No file uploaded (field "file")');
    if (stored.size === 0) {
      await app.blobs.release(stored.sha256);
      throw badRequest('The uploaded file is empty');
    }
    const fh = await open(stored.path, 'r');
    const head = Buffer.alloc(512);
    const { bytesRead } = await fh.read(head, 0, 512, 0);
    await fh.close();
    const fmt = detectNmapFormat(head.subarray(0, bytesRead).toString('utf8'));
    if (fmt === 'unknown') {
      await app.blobs.release(stored.sha256);
      throw badRequest('Not recognised as nmap XML (-oX) or normal (-oN) output');
    }
    const scanId = newId('scan');
    const ts = nowIso();
    const meta: ScanMeta = {
      id: scanId,
      name: name || fileName,
      phase: ScanPhaseSchema.catch('other').parse(phase ?? 'other'),
      fmt: ScanFormatSchema.parse(fmt),
      args: '',
      nmapVersion: '',
      startedAt: '',
      finishedAt: '',
      elapsedS: null,
      hostsUp: 0,
      hostsDown: 0,
      hostsTotal: 0,
      rawSha256: stored.sha256,
      uploadedBy: user.id,
      uploadedByName: user.displayName,
      uploadedAt: ts,
      status: 'parsing',
      error: '',
    };
    app.db.run(
      'INSERT INTO scans (id, case_id, name, phase, fmt, raw_sha256, uploaded_by, uploaded_by_name, uploaded_at, status) VALUES (?,?,?,?,?,?,?,?,?,?)',
      scanId,
      caseId,
      meta.name,
      meta.phase,
      meta.fmt,
      meta.rawSha256,
      meta.uploadedBy,
      meta.uploadedByName,
      meta.uploadedAt,
      'parsing',
    );
    const rt = app.runtimes.get(caseId);
    const actor = { id: user.id, name: user.displayName };
    const added = rt.appendOp(actor, { type: 'scan.add', scan: meta } satisfies Op, {
      canEdit: access.edit,
    });
    if (!added.ok) throw new HttpError(400, added.message, added.code);
    rt.broadcast({ t: 'op', ...added.broadcast });

    // Ingest in the background; progress and completion reach clients over the WebSocket.
    const finish = ingestScan(app, scanId, stored.path, fmt, (hosts) =>
      rt.broadcast({ t: 'scan', scanId, status: 'parsing', hosts }),
    ).then((r) => {
      const row = app.db.get<ScanRow>('SELECT * FROM scans WHERE id = ?', scanId);
      if (!row) return;
      const m = scanRowToMeta(row);
      const inferred = r.ok && phase === undefined && m.args ? inferPhase(m.args) : m.phase;
      const patch = r.ok
        ? {
            status: 'ready' as const,
            args: m.args,
            nmapVersion: m.nmapVersion,
            startedAt: m.startedAt,
            finishedAt: m.finishedAt,
            elapsedS: m.elapsedS,
            hostsUp: m.hostsUp,
            hostsDown: m.hostsDown,
            hostsTotal: m.hostsTotal,
            phase: inferred,
          }
        : { status: 'failed' as const, error: r.error ?? 'unknown error' };
      if (r.ok && inferred !== m.phase)
        app.db.run('UPDATE scans SET phase = ? WHERE id = ?', inferred, scanId);
      const set = rt.appendOp(actor, { type: 'scan.set', id: scanId, patch }, { canEdit: true });
      if (set.ok) rt.broadcast({ t: 'op', ...set.broadcast });
      rt.broadcast({
        t: 'scan',
        scanId,
        status: r.ok ? 'ready' : 'failed',
        hosts: r.hosts,
        error: r.error,
      });
    });
    app.pendingIngests.add(finish);
    void finish.finally(() => app.pendingIngests.delete(finish));

    reply.status(201);
    return { scan: meta };
  });

  app.get<{ Params: { id: string; scanId: string }; Querystring: Record<string, string> }>(
    '/api/cases/:id/scans/:scanId/hosts',
    async (req) => {
      accessOrThrow(app, req, req.params.id, 'read');
      loadScan(app, req.params.id, req.params.scanId);
      const q = HostsQuery.parse(req.query);
      const where: string[] = ['sh.scan_id = ?'];
      const params: (string | number)[] = [req.params.scanId];
      if (q.after) {
        where.push('sh.ip_sort > ?');
        params.push(q.after);
      }
      if (q.net) {
        where.push('sh.net_key = ?');
        params.push(q.net);
      }
      if (q.bucket) {
        where.push('sh.bucket = ?');
        params.push(q.bucket);
      }
      if (q.flagged === '1') where.push(`sh.flags != '[]'`);
      if (q.port !== undefined) {
        where.push(
          'EXISTS (SELECT 1 FROM scan_ports sp WHERE sp.scan_host_id = sh.id AND sp.port = ?)',
        );
        params.push(q.port);
      }
      if (q.q) {
        where.push(
          '(sh.ip LIKE ? OR sh.hostnames LIKE ? OR sh.os_name LIKE ? OR sh.vendor LIKE ? OR sh.mac LIKE ? OR EXISTS (SELECT 1 FROM scan_ports sp WHERE sp.scan_host_id = sh.id AND (sp.name LIKE ? OR sp.product LIKE ?)))',
        );
        const like = `%${q.q.replace(/[%_]/g, '')}%`;
        params.push(like, like, like, like, like, like, like);
      }
      const rows = app.db.all<HostRow>(
        `SELECT sh.* FROM scan_hosts sh WHERE ${where.join(' AND ')} ORDER BY sh.ip_sort LIMIT ?`,
        ...params,
        q.limit + 1,
      );
      const more = rows.length > q.limit;
      const page = more ? rows.slice(0, q.limit) : rows;
      const items = page.map((r) => rowToSummary(app, r));
      const last = page[page.length - 1];
      return { items, next: more && last ? last.ip_sort : null };
    },
  );

  app.get<{ Params: { id: string; scanId: string; ip: string } }>(
    '/api/cases/:id/scans/:scanId/hosts/:ip',
    async (req) => {
      accessOrThrow(app, req, req.params.id, 'read');
      const r = app.db.get<HostRow>(
        'SELECT * FROM scan_hosts WHERE scan_id = ? AND ip = ?',
        req.params.scanId,
        req.params.ip,
      );
      if (!r) throw notFound('No such host in this scan');
      return { host: rowToFull(app, r) };
    },
  );

  app.get<{ Params: { id: string; scanId: string }; Querystring: Record<string, string> }>(
    '/api/cases/:id/scans/:scanId/map',
    async (req) => {
      accessOrThrow(app, req, req.params.id, 'read');
      loadScan(app, req.params.id, req.params.scanId);
      const q = MapQuery.parse(req.query);
      if (q.layout === 'trace') {
        const rows = app.db.all<HostRow>(
          'SELECT sh.* FROM scan_hosts sh WHERE sh.scan_id = ? AND EXISTS (SELECT 1 FROM scan_hops h WHERE h.scan_host_id = sh.id) ORDER BY sh.ip_sort LIMIT 5000',
          req.params.scanId,
        );
        const hosts = rows.map((r) => ({
          ...rowToSummary(app, r),
          trace: app.db
            .all<{ ttl: number; ip: string; host: string; rtt: string }>(
              'SELECT ttl, ip, host, rtt FROM scan_hops WHERE scan_host_id = ? ORDER BY ttl',
              r.id,
            )
            .map((h): Hop => ({ ttl: Number(h.ttl), ip: h.ip, host: h.host, rtt: h.rtt })),
        }));
        return { layout: 'trace', hosts };
      }
      if (q.net) {
        const rows = app.db.all<HostRow>(
          'SELECT * FROM scan_hosts WHERE scan_id = ? AND net_key = ? ORDER BY ip_sort LIMIT 1024',
          req.params.scanId,
          q.net,
        );
        return { layout: 'subnet', net: q.net, hosts: rows.map((r) => rowToSummary(app, r)) };
      }
      let nets: NetAggregate[];
      if (q.bits === 24) {
        const rows = app.db.all<{
          net_key: string;
          hosts: number;
          open_ports: number;
          flagged: number;
        }>(
          `SELECT net_key, COUNT(*) AS hosts, SUM(open_count) AS open_ports, SUM(CASE WHEN flags != '[]' THEN 1 ELSE 0 END) AS flagged FROM scan_hosts WHERE scan_id = ? GROUP BY net_key`,
          req.params.scanId,
        );
        const buckets = app.db.all<{ net_key: string; bucket: string; n: number }>(
          'SELECT net_key, bucket, COUNT(*) AS n FROM scan_hosts WHERE scan_id = ? GROUP BY net_key, bucket',
          req.params.scanId,
        );
        const byNet = new Map<string, NetAggregate>();
        for (const r of rows)
          byNet.set(r.net_key, {
            netKey: r.net_key,
            hosts: Number(r.hosts),
            openPorts: Number(r.open_ports),
            flagged: Number(r.flagged),
            buckets: {},
          });
        for (const b of buckets) byNet.get(b.net_key)!.buckets[b.bucket] = Number(b.n);
        nets = [...byNet.values()].sort((a, b) =>
          compareIps(a.netKey.split('/')[0] ?? a.netKey, b.netKey.split('/')[0] ?? b.netKey),
        );
      } else {
        const rows = app.db.all<{ ip: string; open_count: number; flags: string; bucket: string }>(
          'SELECT ip, open_count, flags, bucket FROM scan_hosts WHERE scan_id = ?',
          req.params.scanId,
        );
        nets = aggregateByNet(
          rows.map((r) => ({
            ip: r.ip,
            openCount: Number(r.open_count),
            flags: JSON.parse(r.flags) as string[],
            bucket: r.bucket,
          })),
          q.bits,
        );
      }
      return { layout: 'subnet', bits: q.bits, nets };
    },
  );

  app.get<{ Params: { id: string; scanId: string } }>(
    '/api/cases/:id/scans/:scanId/targets.txt',
    async (req, reply) => {
      accessOrThrow(app, req, req.params.id, 'read');
      loadScan(app, req.params.id, req.params.scanId);
      const rows = app.db.all<{ ip: string }>(
        `SELECT ip FROM scan_hosts WHERE scan_id = ? AND state = 'up' ORDER BY ip_sort`,
        req.params.scanId,
      );
      return reply
        .type('text/plain; charset=utf-8')
        .header('content-disposition', `attachment; filename="${req.params.scanId}-targets.txt"`)
        .send(rows.map((r) => r.ip).join('\n') + '\n');
    },
  );

  app.get<{ Params: { id: string; scanId: string } }>(
    '/api/cases/:id/scans/:scanId/raw',
    async (req, reply) => {
      accessOrThrow(app, req, req.params.id, 'read');
      const s = loadScan(app, req.params.id, req.params.scanId);
      const ext = s.fmt === 'xml' ? 'xml' : 'nmap';
      return reply
        .type(s.fmt === 'xml' ? 'application/xml' : 'text/plain')
        .header(
          'content-disposition',
          `attachment; filename="${s.name.replace(/[^\w.-]+/g, '_')}.${ext}"`,
        )
        .send(app.blobs.open(s.raw_sha256));
    },
  );

  app.delete<{ Params: { id: string; scanId: string } }>(
    '/api/cases/:id/scans/:scanId',
    async (req) => {
      const { user, access } = accessOrThrow(app, req, req.params.id, 'edit');
      const s = loadScan(app, req.params.id, req.params.scanId);
      const rt = app.runtimes.get(req.params.id);
      const r = rt.appendOp(
        { id: user.id, name: user.displayName },
        { type: 'scan.remove', id: s.id },
        { canEdit: access.edit },
      );
      if (!r.ok) throw new HttpError(400, r.message, r.code);
      rt.broadcast({ t: 'op', ...r.broadcast });
      deleteScanRows(app.db, s.id);
      app.db.run('DELETE FROM scans WHERE id = ?', s.id);
      await app.blobs.release(s.raw_sha256);
      return { ok: true };
    },
  );
}
