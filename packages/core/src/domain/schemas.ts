import { z } from 'zod';

const str = z.string().default('');
const tags = z.array(z.string()).default([]);

export const HostStatusSchema = z.enum([
  'compromised',
  'suspect',
  'contained',
  'remediated',
  'clean',
  'unknown',
]);
export const CriticalitySchema = z.enum(['crown jewel', 'high', 'moderate', 'low']);
export const ConfidenceSchema = z.enum(['confirmed', 'high', 'medium', 'low', 'suspected']);
export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);
export const ScanPhaseSchema = z.enum(['discovery', 'service', 'other']);
export const ScanFormatSchema = z.enum(['xml', 'text']);
export const ScanStatusSchema = z.enum(['parsing', 'ready', 'failed']);

export const CaseMetaSchema = z.object({
  name: str,
  number: str,
  analyst: str,
  classification: str,
  summary: str,
  created: str,
  modified: str,
});

export const HostFieldsSchema = z.object({
  name: str,
  ip: str,
  os: str,
  role: str,
  zone: str,
  crit: CriticalitySchema.catch('moderate'),
  status: HostStatusSchema.catch('unknown'),
  owner: str,
  tags,
  notes: str,
});
export const HostSchema = HostFieldsSchema.extend({ id: z.string().min(1) });

export const EventFieldsSchema = z.object({
  ts: str,
  off: z.coerce.number().int().catch(0),
  hostId: str,
  srcHostId: str,
  user: str,
  priv: str,
  indicator: str,
  itype: str,
  activity: str,
  cmd: str,
  tactic: str,
  technique: str,
  source: str,
  link: str,
  conf: ConfidenceSchema.catch('medium'),
  sev: SeveritySchema.catch('medium'),
  key: z.coerce.boolean().catch(false),
  tags,
  evidence: str,
  notes: str,
});
export const EventSchema = EventFieldsSchema.extend({ id: z.string().min(1) });

export const ScanFieldsSchema = z.object({
  name: str,
  phase: ScanPhaseSchema.catch('other'),
  fmt: ScanFormatSchema.catch('xml'),
  args: str,
  nmapVersion: str,
  startedAt: str,
  finishedAt: str,
  elapsedS: z.number().nullable().default(null),
  hostsUp: z.number().int().nonnegative().default(0),
  hostsDown: z.number().int().nonnegative().default(0),
  hostsTotal: z.number().int().nonnegative().default(0),
  rawSha256: str,
  uploadedBy: str,
  uploadedByName: str,
  uploadedAt: str,
  status: ScanStatusSchema.catch('ready'),
  error: str,
});
export const ScanMetaSchema = ScanFieldsSchema.extend({ id: z.string().min(1) });

export const LinkSchema = z.object({ hostId: z.string().min(1), ip: z.string().min(1) });

export const AttachmentTargetSchema = z.object({
  kind: z.enum(['event', 'host']),
  id: z.string().min(1),
});
export const AttachmentMetaSchema = z.object({
  id: z.string().min(1),
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
  size: z.number().int().nonnegative(),
  mime: str,
  name: str,
  target: AttachmentTargetSchema,
  uploadedBy: str,
  uploadedByName: str,
  createdAt: str,
  // Every field present with a default, like hosts and events: an inverse patch can only set a
  // key back to a prior value, never remove it, so optional keys would break revert.
  md5: z
    .string()
    .regex(/^([0-9a-f]{32})?$/)
    .default(''),
  note: str,
  dangerous: z.boolean().default(false),
});

export const CaseStateSchema = z.object({
  case: CaseMetaSchema,
  hosts: z.record(z.string(), HostSchema),
  events: z.record(z.string(), EventSchema),
  scans: z.record(z.string(), ScanMetaSchema),
  links: z.record(z.string(), LinkSchema),
  attachments: z.record(z.string(), AttachmentMetaSchema),
});

/*
 * Patch schemas are strict: no defaults, no `.catch()`. A patch must carry only the keys being
 * changed, and an absent key must stay absent, otherwise per-field last-write-wins would reset
 * every other field to its default on each edit. Invalid values are rejected, not coerced.
 */
const s = z.string();
export const CasePatchSchema = z
  .object({
    name: s,
    number: s,
    analyst: s,
    classification: s,
    summary: s,
    created: s,
    modified: s,
  })
  .partial();
export const HostPatchSchema = z
  .object({
    name: s,
    ip: s,
    os: s,
    role: s,
    zone: s,
    crit: CriticalitySchema,
    status: HostStatusSchema,
    owner: s,
    tags: z.array(z.string()),
    notes: s,
  })
  .partial();
export const EventPatchSchema = z
  .object({
    ts: s,
    off: z.number().int(),
    hostId: s,
    srcHostId: s,
    user: s,
    priv: s,
    indicator: s,
    itype: s,
    activity: s,
    cmd: s,
    tactic: s,
    technique: s,
    source: s,
    link: s,
    conf: ConfidenceSchema,
    sev: SeveritySchema,
    key: z.boolean(),
    tags: z.array(z.string()),
    evidence: s,
    notes: s,
  })
  .partial();
/** Only the note is editable after upload; the bytes, hashes and danger flag are the record. */
export const AttachmentPatchSchema = z.object({ note: s }).partial();
export const ScanPatchSchema = z
  .object({
    name: s,
    phase: ScanPhaseSchema,
    fmt: ScanFormatSchema,
    args: s,
    nmapVersion: s,
    startedAt: s,
    finishedAt: s,
    elapsedS: z.number().nullable(),
    hostsUp: z.number().int().nonnegative(),
    hostsDown: z.number().int().nonnegative(),
    hostsTotal: z.number().int().nonnegative(),
    rawSha256: s,
    uploadedBy: s,
    uploadedAt: s,
    status: ScanStatusSchema,
    error: s,
  })
  .partial();
