/**
 * Terrain access behind one interface so the views work the same in both modes:
 * ServerTerrain pages from the API, MemoryTerrain holds parsed scans in the page.
 *
 * Case-status overlay is never fetched: the client maps each terrain IP to a case host with
 * `caseHostByIp`, so changing a host's status recolours the map without a round trip.
 */
import {
  aggregateByNet,
  inferPhase,
  matchesTerrainFilter,
  pageTerrainHosts,
  sortTerrainHosts,
  toTerrainSummary,
  type NetAggregate,
  type ScanHost,
  type ScanMeta,
  type ScanRunMeta,
  type TerrainFilter,
  type TerrainHostSummary,
  type TerrainTraceHost,
} from '@midden/core';
import { api } from './api';

export interface TerrainPageResult {
  items: TerrainHostSummary[];
  next: string | null;
}

export interface TerrainStore {
  /** Can this store accept new scans (edit access / standalone)? */
  readonly canUpload: boolean;
  mapSummary(scanId: string, bits: number): Promise<NetAggregate[]>;
  hostsInNet(scanId: string, net: string): Promise<TerrainHostSummary[]>;
  hostsPage(
    scanId: string,
    after: string | null,
    limit: number,
    filter: TerrainFilter,
  ): Promise<TerrainPageResult>;
  hostDetail(scanId: string, ip: string): Promise<ScanHost>;
  traceHosts(scanId: string): Promise<TerrainTraceHost[]>;
  targets(scanId: string): Promise<string[]>;
  removeScan(scanId: string): Promise<void>;
}

const qs = (o: Record<string, string | number | undefined>): string =>
  Object.entries(o)
    .filter(([, v]) => v !== undefined && v !== '')
    .map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`)
    .join('&');

export class ServerTerrain implements TerrainStore {
  constructor(
    private readonly caseId: string,
    readonly canUpload: boolean,
  ) {}
  private base(scanId: string): string {
    return `/api/cases/${this.caseId}/scans/${scanId}`;
  }
  async mapSummary(scanId: string, bits: number): Promise<NetAggregate[]> {
    const r = await api<{ nets: NetAggregate[] }>(
      'GET',
      `${this.base(scanId)}/map?${qs({ layout: 'subnet', bits })}`,
    );
    return r.nets;
  }
  async hostsInNet(scanId: string, net: string): Promise<TerrainHostSummary[]> {
    const r = await api<{ hosts: TerrainHostSummary[] }>(
      'GET',
      `${this.base(scanId)}/map?${qs({ net })}`,
    );
    return r.hosts;
  }
  async hostsPage(
    scanId: string,
    after: string | null,
    limit: number,
    filter: TerrainFilter,
  ): Promise<TerrainPageResult> {
    return api<TerrainPageResult>(
      'GET',
      `${this.base(scanId)}/hosts?${qs({ after: after ?? undefined, limit, net: filter.net, port: filter.port, bucket: filter.bucket, q: filter.q, flagged: filter.flagged ? '1' : undefined })}`,
    );
  }
  async hostDetail(scanId: string, ip: string): Promise<ScanHost> {
    const r = await api<{ host: ScanHost }>(
      'GET',
      `${this.base(scanId)}/hosts/${encodeURIComponent(ip)}`,
    );
    return r.host;
  }
  async traceHosts(scanId: string): Promise<TerrainTraceHost[]> {
    const r = await api<{ hosts: TerrainTraceHost[] }>(
      'GET',
      `${this.base(scanId)}/map?layout=trace`,
    );
    return r.hosts;
  }
  async targets(scanId: string): Promise<string[]> {
    const res = await fetch(`${this.base(scanId)}/targets.txt`, { credentials: 'same-origin' });
    return (await res.text()).split('\n').filter(Boolean);
  }
  async removeScan(scanId: string): Promise<void> {
    await api('DELETE', this.base(scanId));
  }
}

/** Standalone: parsed scans live in the page and travel in the v2 case file. */
export class MemoryTerrain implements TerrainStore {
  readonly canUpload = true;
  private readonly scans = new Map<string, ScanHost[]>();

  constructor(initial: Record<string, ScanHost[]> = {}) {
    for (const [id, hosts] of Object.entries(initial)) this.scans.set(id, sortTerrainHosts(hosts));
  }
  put(scanId: string, hosts: ScanHost[]): void {
    this.scans.set(scanId, sortTerrainHosts(hosts));
  }
  all(): Record<string, ScanHost[]> {
    return Object.fromEntries(this.scans);
  }
  has(scanId: string): boolean {
    return this.scans.has(scanId);
  }
  private get(scanId: string): ScanHost[] {
    return this.scans.get(scanId) ?? [];
  }
  async mapSummary(scanId: string, bits: number): Promise<NetAggregate[]> {
    return aggregateByNet(this.get(scanId), bits);
  }
  async hostsInNet(scanId: string, net: string): Promise<TerrainHostSummary[]> {
    return this.get(scanId)
      .filter((h) => matchesTerrainFilter(h, { net }))
      .map(toTerrainSummary);
  }
  async hostsPage(
    scanId: string,
    after: string | null,
    limit: number,
    filter: TerrainFilter,
  ): Promise<TerrainPageResult> {
    const matching = this.get(scanId).filter((h) => matchesTerrainFilter(h, filter));
    const page = pageTerrainHosts(matching, after, limit);
    return { items: page.items.map(toTerrainSummary), next: page.next };
  }
  async hostDetail(scanId: string, ip: string): Promise<ScanHost> {
    const h = this.get(scanId).find((x) => x.ip === ip);
    if (!h) throw new Error(`No host ${ip} in this scan`);
    return h;
  }
  async traceHosts(scanId: string): Promise<TerrainTraceHost[]> {
    return this.get(scanId)
      .filter((h) => h.trace.length)
      .map((h) => ({ ...toTerrainSummary(h), trace: h.trace }));
  }
  async targets(scanId: string): Promise<string[]> {
    return this.get(scanId)
      .filter((h) => h.state === 'up')
      .map((h) => h.ip);
  }
  async removeScan(scanId: string): Promise<void> {
    this.scans.delete(scanId);
  }
}

/** Scan metadata built locally after a standalone parse. */
export function scanMetaFromParse(
  id: string,
  name: string,
  meta: ScanRunMeta,
  hosts: number,
  now: string,
): ScanMeta {
  return {
    id,
    name,
    // Same inference the server does, so a standalone scan lands in the right workflow phase.
    phase: meta.args ? inferPhase(meta.args) : 'other',
    fmt: meta.fmt,
    args: meta.args,
    nmapVersion: meta.version,
    startedAt: meta.start,
    finishedAt: meta.end,
    elapsedS: meta.elapsed ? Number(meta.elapsed) : null,
    hostsUp: meta.hostsUp ?? hosts,
    hostsDown: meta.hostsDown ?? 0,
    hostsTotal: meta.hostsTotal ?? meta.hostsUp ?? hosts,
    rawSha256: '',
    uploadedBy: 'local',
    uploadedByName: '',
    uploadedAt: now,
    status: 'ready',
    error: '',
  };
}
