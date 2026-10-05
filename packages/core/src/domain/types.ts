/**
 * Case-state domain types. These are the small, op-logged, fully-replicated entities.
 * Terrain (scanned hosts and ports) lives in `nmap/types.ts` and is never part of CaseState.
 *
 * Field names and semantics for CaseMeta, Host and Event are kept identical to the
 * original prototype so `midden.case.v1` files round-trip without translation.
 */

export interface CaseMeta {
  name: string;
  number: string;
  analyst: string;
  classification: string;
  summary: string;
  /** ISO-8601 UTC. */
  created: string;
  /** ISO-8601 UTC. */
  modified: string;
}

export type HostStatus =
  'compromised' | 'suspect' | 'contained' | 'remediated' | 'clean' | 'unknown';
export type Criticality = 'crown jewel' | 'high' | 'moderate' | 'low';

export interface Host {
  id: string;
  name: string;
  /** Free text; may hold several addresses. Use `hostIps()` to extract them. */
  ip: string;
  os: string;
  role: string;
  zone: string;
  crit: Criticality;
  status: HostStatus;
  owner: string;
  tags: string[];
  notes: string;
}

export type Confidence = 'confirmed' | 'high' | 'medium' | 'low' | 'suspected';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Event {
  id: string;
  /** ISO-8601 UTC instant. */
  ts: string;
  /** Source-system timezone offset in minutes east of UTC, so the original local time can be shown. */
  off: number;
  hostId: string;
  /** Pivot source host; empty when the event is not a lateral move. */
  srcHostId: string;
  user: string;
  priv: string;
  indicator: string;
  itype: string;
  activity: string;
  cmd: string;
  /** ATT&CK tactic id, e.g. TA0008. */
  tactic: string;
  /** ATT&CK technique id, e.g. T1021.002. */
  technique: string;
  source: string;
  link: string;
  conf: Confidence;
  sev: Severity;
  key: boolean;
  tags: string[];
  evidence: string;
  notes: string;
}

export type ScanPhase = 'discovery' | 'service' | 'other';
export type ScanFormat = 'xml' | 'text';
export type ScanStatus = 'parsing' | 'ready' | 'failed';

/** Registration of an uploaded scan. The parsed hosts live in terrain storage, keyed by `id`. */
export interface ScanMeta {
  id: string;
  name: string;
  phase: ScanPhase;
  fmt: ScanFormat;
  args: string;
  nmapVersion: string;
  startedAt: string;
  finishedAt: string;
  elapsedS: number | null;
  hostsUp: number;
  hostsDown: number;
  hostsTotal: number;
  rawSha256: string;
  uploadedBy: string;
  /** Display name of the uploader, captured at upload time (empty for local/legacy scans). */
  uploadedByName: string;
  uploadedAt: string;
  status: ScanStatus;
  error: string;
}

/** Manual association between a case host and an address seen in terrain. */
export interface Link {
  hostId: string;
  ip: string;
}

export type AttachmentTarget = { kind: 'event' | 'host'; id: string };

export interface AttachmentMeta {
  id: string;
  sha256: string;
  size: number;
  mime: string;
  name: string;
  target: AttachmentTarget;
  uploadedBy: string;
  /** Display name at the time of upload, kept on the record so custody reads without a user lookup. */
  uploadedByName: string;
  createdAt: string;
  /** Hex MD5 of the stored bytes, alongside sha256, because that is what most threat intel still keys on. */
  md5: string;
  /** Analyst's note about the file: where it came from, what it is. The one field editable after upload. */
  note: string;
  /**
   * Malware, a weaponised document, or anything else an analyst must not open by accident. The
   * stored bytes are untouched (the hash is the sample's hash); the download is wrapped instead.
   */
  dangerous: boolean;
}
export type AttachmentFields = Omit<AttachmentMeta, 'id'>;

export interface CaseState {
  case: CaseMeta;
  hosts: Record<string, Host>;
  events: Record<string, Event>;
  scans: Record<string, ScanMeta>;
  /** Keyed by `linkKey(hostId, ip)`. */
  links: Record<string, Link>;
  attachments: Record<string, AttachmentMeta>;
}

export const linkKey = (hostId: string, ip: string): string => `${hostId}|${ip}`;

/** Fields of a Host that may be patched (everything except the id). */
export type HostFields = Omit<Host, 'id'>;
export type EventFields = Omit<Event, 'id'>;
export type ScanFields = Omit<ScanMeta, 'id'>;
