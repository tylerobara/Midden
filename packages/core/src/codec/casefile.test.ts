import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { CaseFileError, mergeOps, readCaseFile, sortedEvents, writeCaseFile } from './casefile.js';
import { demoCaseState } from '../demo/demoCase.js';
import { apply, emptyState } from '../ops/reducer.js';
import { CASE_SCHEMA_V2 } from '../schema/versions.js';

const fixture = (name: string): unknown =>
  JSON.parse(readFileSync(new URL(`../../fixtures/${name}`, import.meta.url), 'utf8'));

describe('readCaseFile v1', () => {
  it('opens a prototype export, applying defaults, remapping duplicates and dropping junk', () => {
    const { state, report } = readCaseFile(fixture('demo-case-v1.json'));
    expect(report.version).toBe(1);
    expect(state.case.name).toBe('Operation Glasshouse');

    // 6 host entries: 4 kept as-is, one duplicate id remapped, one without id assigned one
    expect(report.hosts).toBe(6);
    expect(report.remapped.filter((r) => r.kind === 'host')).toHaveLength(1);
    const names = Object.values(state.hosts)
      .map((h) => h.name)
      .sort();
    expect(names).toEqual([
      'DC-CORP-01',
      'DUPLICATE-ID',
      'NO-ID',
      'OLD-BOX',
      'SRV-FILE-02',
      'WKS-FIN-014',
    ]);
    const legacy = Object.values(state.hosts).find((h) => h.name === 'OLD-BOX')!;
    expect(legacy.crit).toBe('moderate');
    expect(legacy.status).toBe('unknown');
    const noId = Object.values(state.hosts).find((h) => h.name === 'NO-ID')!;
    expect(noId.id).toMatch(/^h_/);
    expect(noId.tags).toEqual([]);

    // events: ev_1, ev_2, ev_3 kept; ev_bad dropped; duplicate ev_1 remapped; string dropped
    expect(report.events).toBe(4);
    expect(report.dropped.map((d) => d.kind)).toEqual(['event', 'event']);
    expect(state.events.ev_3?.conf).toBe('medium');
    expect(state.events.ev_3?.off).toBe(0);
    expect(state.events.ev_2?.off).toBe(-300);
    expect((state.events.ev_1 as unknown as { ep?: number }).ep).toBeUndefined();
    expect(report.remapped.filter((r) => r.kind === 'event')).toHaveLength(1);
  });

  it('rejects things that are not case files', () => {
    expect(() => readCaseFile({ foo: 1 })).toThrow(CaseFileError);
    expect(() => readCaseFile('nope')).toThrow(CaseFileError);
    expect(() => readCaseFile({ schema: 'midden.case.v9', hosts: [], events: [] })).toThrow(
      /Unsupported/,
    );
  });

  it('accepts a bare {hosts, events} object with no schema, like the prototype does', () => {
    const { state, report } = readCaseFile({ hosts: [], events: [] });
    expect(report.version).toBe(1);
    expect(state.case.created).toBeTruthy();
  });
});

describe('write / read v2 round trip', () => {
  it('round-trips the demo case and keeps v1-compatible shapes', () => {
    const demo = demoCaseState();
    const file = writeCaseFile(demo, { now: '2026-07-15T10:00:00.000Z' });
    expect(file.schema).toBe(CASE_SCHEMA_V2);
    expect(file.hosts).toHaveLength(5);
    expect(file.events.map((e) => e.id)).toEqual(sortedEvents(demo).map((e) => e.id));
    // v1 compatibility: flat event with numeric offset and no derived fields
    const ev = file.events[0]!;
    expect(typeof ev.off).toBe('number');
    expect('ep' in ev).toBe(false);
    expect(file.scans).toEqual([]);

    const back = readCaseFile(JSON.parse(JSON.stringify(file)));
    expect(back.report.version).toBe(2);
    expect(back.state).toEqual(demo);
  });

  it('embeds and restores terrain and attachment payloads', () => {
    let s = demoCaseState();
    s = apply(s, {
      type: 'scan.add',
      scan: {
        id: 'scan_1',
        name: 'discovery',
        phase: 'discovery',
        fmt: 'xml',
        args: 'nmap -sn 10.20.0.0/16',
        nmapVersion: '7.98',
        startedAt: '',
        finishedAt: '',
        elapsedS: 12,
        hostsUp: 1,
        hostsDown: 0,
        hostsTotal: 1,
        rawSha256: 'a'.repeat(64),
        uploadedBy: 'u1',
        uploadedByName: 'Ann',
        uploadedAt: '2026-07-15T10:00:00.000Z',
        status: 'ready',
        error: '',
      },
    });
    s = apply(s, { type: 'link.set', hostId: 'h_dc', ip: '10.20.1.5' });
    s = apply(s, {
      type: 'attachment.add',
      att: {
        id: 'att_1',
        sha256: 'b'.repeat(64),
        size: 3,
        mime: 'text/plain',
        name: 'note.txt',
        target: { kind: 'event', id: 'ev_demo_01' },
        uploadedBy: 'u1',
        uploadedByName: 'Ann',
        createdAt: '2026-07-15T10:00:00.000Z',
        md5: 'c'.repeat(32),
        note: '',
        dangerous: false,
      },
    });
    const host = {
      ip: '10.20.1.5',
      ipv6: '',
      mac: '',
      vendor: '',
      hostnames: ['dc'],
      state: 'up',
      reason: '',
      latency: '',
      distance: null,
      ports: [],
      osName: '',
      osAccuracy: '',
      osFamily: '',
      osVendor: '',
      osType: '',
      trace: [],
      scripts: [],
      uptime: '',
      bucket: 'Windows',
      role: 'Domain controller',
      flags: [],
      openCount: 0,
    };
    const file = writeCaseFile(s, {
      terrain: { scan_1: [host] },
      attachmentData: { att_1: 'aGV5' },
    });
    expect(file.scans[0]?.hosts).toHaveLength(1);
    expect(file.attachments[0]?.data).toBe('aGV5');
    const back = readCaseFile(JSON.parse(JSON.stringify(file)));
    expect(back.state).toEqual(s);
    expect(back.terrain.scan_1).toEqual([host]);
    expect(back.attachmentData.att_1).toBe('aGV5');
  });
});

describe('mergeOps', () => {
  it('adds only unknown ids', () => {
    const demo = demoCaseState();
    const partial = emptyState();
    partial.hosts.h_wks = demo.hosts.h_wks!;
    partial.events.ev_demo_01 = demo.events.ev_demo_01!;
    const op = mergeOps(partial, demo);
    expect(op.type).toBe('batch');
    if (op.type !== 'batch') throw new Error();
    expect(op.ops.filter((o) => o.type === 'host.add')).toHaveLength(4);
    expect(op.ops.filter((o) => o.type === 'event.add')).toHaveLength(13);
    expect(apply(partial, op)).toEqual({ ...demo, case: partial.case });
  });
});
