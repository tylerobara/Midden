import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { demoCaseState, emptyState } from '@midden/core';
import { LocalFileStore } from '../store/LocalFileStore';
import { useCaseStore } from '../store/useCaseStore';
import { useTerrain } from '../store/useTerrain';
import { MemoryTerrain } from './terrain';
import {
  AUTOSAVE_KEY,
  clearAutosave,
  readAutosave,
  restoreAutosave,
  saveNow,
  startAutosave,
  useAutosave,
} from './autosave';

describe('standalone autosave', () => {
  beforeEach(() => {
    localStorage.clear();
    useCaseStore.getState().attachAdapter(new LocalFileStore(emptyState()));
    useTerrain.getState().setStore(new MemoryTerrain());
    useAutosave.setState({ status: { kind: 'idle' } });
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('round-trips the case, its scans, the file name and the dirty flag', async () => {
    await useCaseStore.getState().replace(demoCaseState(), { fileName: 'glasshouse.json' });
    await useCaseStore.getState().dispatch({
      type: 'host.set',
      id: 'h_vpn',
      patch: { notes: 'edited after the last file save' },
    });
    // terrain travels with the file only for scans the case knows about
    await useCaseStore.getState().dispatch({
      type: 'scan.add',
      scan: {
        id: 'scan_1',
        name: 'lab',
        phase: 'discovery',
        fmt: 'xml',
        args: '',
        nmapVersion: '',
        startedAt: '',
        finishedAt: '',
        elapsedS: null,
        hostsUp: 1,
        hostsDown: 0,
        hostsTotal: 1,
        rawSha256: '',
        uploadedBy: 'local',
        uploadedByName: '',
        uploadedAt: '2026-07-15T10:00:00.000Z',
        status: 'ready',
        error: '',
      },
    });
    useTerrain.getState().setStore(
      new MemoryTerrain({
        scan_1: [
          {
            ip: '10.0.0.1',
            ipv6: '',
            mac: '',
            vendor: '',
            hostnames: [],
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
            bucket: 'Other',
            role: '',
            flags: [],
            openCount: 0,
          },
        ],
      }),
    );
    expect(useCaseStore.getState().dirty).toBe(true);
    saveNow();
    expect(useAutosave.getState().status).toMatchObject({ kind: 'saved', dropped: 'nothing' });

    // a fresh session: empty case, then restore
    useCaseStore.getState().attachAdapter(new LocalFileStore(emptyState()));
    useTerrain.getState().setStore(new MemoryTerrain());
    const restored = await restoreAutosave();
    expect(restored?.events).toBe(Object.keys(demoCaseState().events).length);
    const cs = useCaseStore.getState();
    expect(cs.state.hosts.h_vpn?.notes).toBe('edited after the last file save');
    expect(cs.fileName).toBe('glasshouse.json');
    expect(cs.dirty).toBe(true);
    const terrain = useTerrain.getState().store;
    expect(terrain instanceof MemoryTerrain && terrain.has('scan_1')).toBe(true);
  });

  it('does not overwrite work already on screen', async () => {
    await useCaseStore.getState().replace(demoCaseState());
    saveNow();
    await useCaseStore.getState().dispatch({ type: 'case.set', patch: { name: 'Current' } });
    expect(await restoreAutosave()).toBeNull();
    expect(useCaseStore.getState().state.case.name).toBe('Current');
  });

  it('ignores corrupt or foreign data instead of throwing', async () => {
    localStorage.setItem(AUTOSAVE_KEY, '{not json');
    expect(readAutosave()).toBeNull();
    localStorage.setItem(AUTOSAVE_KEY, JSON.stringify({ file: { schema: 'something.else' } }));
    // readCaseFile tolerates unknown shapes by dropping what it cannot read
    expect(await restoreAutosave()).toBeNull();
  });

  it('drops the scan data first when the browser is out of room', async () => {
    await useCaseStore.getState().replace(demoCaseState());
    let calls = 0;
    const real = Storage.prototype.setItem;
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(function (this: Storage, k, v) {
      calls += 1;
      if (calls === 1) throw new DOMException('quota', 'QuotaExceededError');
      real.call(this, k, v);
    });
    saveNow();
    expect(useAutosave.getState().status).toMatchObject({ kind: 'saved', dropped: 'terrain' });
    expect(readAutosave()?.parsed.report.events).toBe(Object.keys(demoCaseState().events).length);
  });

  it('reports when even the case alone will not fit', async () => {
    await useCaseStore.getState().replace(demoCaseState());
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('quota', 'QuotaExceededError');
    });
    saveNow();
    expect(useAutosave.getState().status).toMatchObject({
      kind: 'failed',
      reason: expect.stringMatching(/too large/),
    });
  });

  it('saves shortly after a change, and at once when the page is hidden', async () => {
    vi.useFakeTimers();
    const stop = startAutosave();
    await useCaseStore.getState().dispatch({ type: 'case.set', patch: { name: 'Typed' } });
    expect(localStorage.getItem(AUTOSAVE_KEY)).toBeNull();
    vi.advanceTimersByTime(500);
    expect(readAutosave()?.parsed.state.case.name).toBe('Typed');

    await useCaseStore.getState().dispatch({ type: 'case.set', patch: { name: 'Typed more' } });
    window.dispatchEvent(new Event('pagehide'));
    expect(readAutosave()?.parsed.state.case.name).toBe('Typed more');
    stop();
    clearAutosave();
    expect(localStorage.getItem(AUTOSAVE_KEY)).toBeNull();
  });
});
