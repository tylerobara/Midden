import { useEffect, useRef, useState } from 'react';
import {
  byId,
  caseHostByIp,
  HOST_STATUS,
  OS_BUCKETS,
  type ScanMeta,
  type TerrainFilter,
  type TerrainHostSummary,
} from '@midden/core';
import { useCaseStore } from '../store/useCaseStore';
import { useUiStore } from '../store/useUiStore';
import { useTerrain } from '../store/useTerrain';
import { downloadTargets, promoteHosts, removeScan, uploadScan } from '../lib/terrainActions';
import { toast } from '../store/useToasts';
import { trunc } from '../lib/format';
import { EmptyState } from './EmptyState';
import { Tag } from '../components/cells';

const HS = byId(HOST_STATUS);
const PAGE = 200;

export function ScansView() {
  const state = useCaseStore((s) => s.state);
  const access = useCaseStore((s) => s.access);
  const scans = Object.values(state.scans).sort((a, b) => (a.uploadedAt < b.uploadedAt ? 1 : -1));
  const { scanId, setScanId, confirm } = useUiStore();
  const selected = (scanId && state.scans[scanId]) || scans[0] || null;

  useEffect(() => {
    if (selected && selected.id !== scanId) setScanId(selected.id);
  }, [selected, scanId, setScanId]);

  if (!scans.length) {
    return <UploadPrompt canUpload={access.edit} />;
  }
  return (
    <>
      <div className="toolbar">
        <UploadButton canUpload={access.edit} />
        <div className="seg" style={{ maxWidth: '55%', overflowX: 'auto' }}>
          {scans.map((s) => (
            <button
              key={s.id}
              className={selected?.id === s.id ? 'on' : ''}
              onClick={() => setScanId(s.id)}
              data-testid="scan-tab"
              title={s.args || s.name}
            >
              {trunc(s.name, 28)}
              {s.status === 'parsing' && ' …'}
              {s.status === 'failed' && ' ✕'}
            </button>
          ))}
        </div>
        <span className="sp" />
        {selected && (
          <>
            <button
              className="btn ghost"
              onClick={() => void downloadTargets(selected.id, selected.name)}
              data-testid="download-targets"
            >
              Alive targets (.txt)
            </button>
            {access.edit && (
              <button
                className="btn ghost mag"
                onClick={() =>
                  confirm(
                    'Remove scan',
                    `Remove "${selected.name}" and its ${selected.hostsUp} parsed hosts? Case hosts promoted from it are kept.`,
                    'Remove scan',
                    () => void removeScan(selected.id),
                    true,
                  )
                }
              >
                Remove
              </button>
            )}
          </>
        )}
      </div>
      {selected && <ScanDetail scan={selected} />}
    </>
  );
}

function UploadPrompt({ canUpload }: { canUpload: boolean }) {
  return (
    <EmptyState
      title="No scans uploaded"
      body="Upload nmap XML (-oX) or normal (-oN) output. Midden parses it into the terrain layer: a searchable host inventory and a network map you can overlay your case hosts onto."
    >
      {canUpload ? (
        <UploadButton canUpload primary />
      ) : (
        <span style={{ color: 'var(--dim)' }}>You do not have edit access to this case.</span>
      )}
    </EmptyState>
  );
}

function UploadButton({ canUpload, primary }: { canUpload: boolean; primary?: boolean }) {
  const input = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  if (!canUpload) return null;
  return (
    <>
      <button
        className={'btn ' + (primary ? 'pri' : '')}
        disabled={busy}
        onClick={() => input.current?.click()}
        data-testid="upload-scan"
      >
        {busy ? 'Parsing…' : '+ Upload scan'}
      </button>
      <input
        ref={input}
        type="file"
        accept=".xml,.nmap,.txt,text/xml,application/xml,text/plain"
        style={{ display: 'none' }}
        data-testid="scan-file-input"
        onChange={(e) => {
          const f = e.target.files?.[0];
          e.target.value = '';
          if (!f) return;
          setBusy(true);
          void uploadScan(f).finally(() => setBusy(false));
        }}
      />
    </>
  );
}

function ScanDetail({ scan }: { scan: ScanMeta }) {
  const state = useCaseStore((s) => s.state);
  const access = useCaseStore((s) => s.access);
  const store = useTerrain((s) => s.store);
  const version = useTerrain((s) => s.version);
  const [filter, setFilter] = useState<TerrainFilter>({});
  const [q, setQ] = useState('');
  const [items, setItems] = useState<TerrainHostSummary[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [openIp, setOpenIp] = useState<string | null>(null);
  const linked = caseHostByIp(state);

  useEffect(() => {
    const t = setTimeout(() => setFilter((f) => ({ ...f, q: q || undefined })), 200);
    return () => clearTimeout(t);
  }, [q]);

  // Resetting derived state while rendering (rather than in an effect) avoids a second pass.
  const requestKey = `${scan.id}|${scan.status}|${version}|${JSON.stringify(filter)}`;
  const [seenKey, setSeenKey] = useState(requestKey);
  if (seenKey !== requestKey) {
    setSeenKey(requestKey);
    setLoading(true);
  }

  useEffect(() => {
    let alive = true;
    store
      .hostsPage(scan.id, null, PAGE, filter)
      .then((r) => {
        if (!alive) return;
        setItems(r.items);
        setNext(r.next);
      })
      .catch((err: unknown) =>
        toast(err instanceof Error ? err.message : 'Could not load hosts', 'bad'),
      )
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [store, requestKey]);

  const more = async (): Promise<void> => {
    const r = await store.hostsPage(scan.id, next, PAGE, filter);
    setItems((cur) => [...cur, ...r.items]);
    setNext(r.next);
  };

  if (scan.status === 'parsing') {
    return (
      <EmptyState
        title="Parsing…"
        body={`Midden is reading ${scan.name}. Hosts appear here as soon as it finishes.`}
      />
    );
  }
  if (scan.status === 'failed') {
    return (
      <EmptyState
        title="That scan could not be parsed"
        body={scan.error || 'The file was not valid nmap output.'}
      />
    );
  }

  return (
    <>
      <div className="fs" style={{ marginBottom: 12 }}>
        <legend>{scan.name}</legend>
        <dl className="kv" style={{ fontSize: 11, marginBottom: 10 }}>
          {scan.args && (
            <>
              <dt>Command</dt>
              <dd>
                <code className="cmd">{scan.args}</code>
              </dd>
            </>
          )}
          <dt>Scan</dt>
          <dd>
            {scan.phase} · nmap {scan.nmapVersion || '?'} · {scan.startedAt || 'unknown start'}
            {scan.elapsedS !== null && ` · ${scan.elapsedS}s`}
            {scan.uploadedByName && ` · by ${scan.uploadedByName}`}
          </dd>
          <dt>Hosts</dt>
          <dd>
            {scan.hostsUp} up{scan.hostsTotal ? ` of ${scan.hostsTotal} addresses` : ''}
          </dd>
        </dl>
        <div className="grid3">
          <div className="field">
            <label htmlFor="tQ">Search</label>
            <input
              id="tQ"
              type="text"
              value={q}
              placeholder="ip, hostname, service, product…"
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="tPort">Open port</label>
            <input
              id="tPort"
              type="number"
              min={0}
              max={65535}
              placeholder="445"
              onChange={(e) =>
                setFilter((f) => ({
                  ...f,
                  port: e.target.value ? Number(e.target.value) : undefined,
                }))
              }
            />
          </div>
          <div className="field">
            <label htmlFor="tBucket">Class</label>
            <select
              id="tBucket"
              onChange={(e) => setFilter((f) => ({ ...f, bucket: e.target.value || undefined }))}
            >
              <option value="">All classes</option>
              {OS_BUCKETS.map((b) => (
                <option key={b} value={b}>
                  {b}
                </option>
              ))}
            </select>
          </div>
          <div className="field span3">
            <label className="ck">
              <input
                type="checkbox"
                onChange={(e) =>
                  setFilter((f) => ({ ...f, flagged: e.target.checked || undefined }))
                }
              />{' '}
              Only hosts running cleartext, legacy or high-value remote-access services
            </label>
          </div>
        </div>
      </div>

      <div className="toolbar">
        <span style={{ color: 'var(--dim)', fontSize: 10, letterSpacing: '.14em' }}>
          {loading ? 'LOADING…' : `${items.length}${next ? '+' : ''} HOSTS`}
        </span>
        <span className="sp" />
        {access.edit && (
          <button
            className="btn"
            onClick={() =>
              void promoteHosts(
                items.filter((h) => !linked.has(h.ip)),
                scan.id,
              )
            }
            disabled={!items.some((h) => !linked.has(h.ip))}
            data-testid="promote-all"
          >
            Add all shown to case
          </button>
        )}
      </div>

      <table className="tbl">
        <thead>
          <tr>
            <th>Address</th>
            <th>Name</th>
            <th>Class / role</th>
            <th>OS</th>
            <th>Open ports</th>
            <th>In case</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {items.map((h) => {
            const caseHostId = linked.get(h.ip);
            const caseHost = caseHostId ? state.hosts[caseHostId] : undefined;
            const open = openIp === h.ip;
            return (
              <FragmentRow key={h.ip}>
                <tr onClick={() => setOpenIp(open ? null : h.ip)} data-testid="terrain-row">
                  <td style={{ color: 'var(--cy)', whiteSpace: 'nowrap' }}>{h.ip}</td>
                  <td>{h.hostnames[0] ?? '—'}</td>
                  <td>
                    {h.bucket}
                    {h.role && <div className="tid">{h.role}</div>}
                  </td>
                  <td className="tw">{trunc(h.osName || '—', 40)}</td>
                  <td>
                    <span style={{ color: 'var(--cy)' }}>{h.openCount}</span>
                    <div className="tid">{trunc(h.ports.map((p) => p.port).join(' '), 40)}</div>
                  </td>
                  <td>
                    {caseHost ? (
                      <Tag color={(HS[caseHost.status] ?? HS.unknown).color}>{caseHost.name}</Tag>
                    ) : (
                      <span style={{ color: 'var(--dimmer)' }}>—</span>
                    )}
                  </td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {h.flags.length > 0 && (
                      <span
                        className="badge"
                        style={{ color: 'var(--am)' }}
                        title={h.flags.join('\n')}
                      >
                        {h.flags.length} flag{h.flags.length === 1 ? '' : 's'}
                      </span>
                    )}{' '}
                    {access.edit && !caseHost && (
                      <button
                        className="btn sm ghost"
                        onClick={(e) => {
                          e.stopPropagation();
                          void promoteHosts([h], scan.id);
                        }}
                        data-testid="promote-host"
                      >
                        Add to case
                      </button>
                    )}
                  </td>
                </tr>
                {open && <HostDetailRow scanId={scan.id} ip={h.ip} summary={h} />}
              </FragmentRow>
            );
          })}
        </tbody>
      </table>
      {next && (
        <div style={{ padding: 12, textAlign: 'center' }}>
          <button className="btn ghost" onClick={() => void more()} data-testid="load-more-hosts">
            Load more
          </button>
        </div>
      )}
    </>
  );
}

function HostDetailRow({
  scanId,
  ip,
  summary,
}: {
  scanId: string;
  ip: string;
  summary: TerrainHostSummary;
}) {
  const store = useTerrain((s) => s.store);
  const [detail, setDetail] = useState<Awaited<ReturnType<typeof store.hostDetail>> | null>(null);
  useEffect(() => {
    let alive = true;
    store
      .hostDetail(scanId, ip)
      .then((d) => alive && setDetail(d))
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [store, scanId, ip]);
  return (
    <tr className="expand">
      <td colSpan={7}>
        <dl className="kv">
          <dt>Addresses</dt>
          <dd>
            {ip}
            {summary.ipv6 && ` · ${summary.ipv6}`}
            {summary.mac && ` · ${summary.mac}${summary.vendor ? ` (${summary.vendor})` : ''}`}
          </dd>
          {summary.hostnames.length > 0 && (
            <>
              <dt>Names</dt>
              <dd>{summary.hostnames.join(', ')}</dd>
            </>
          )}
          <dt>Detected</dt>
          <dd>
            {summary.osName || 'no OS match'}
            {summary.osAccuracy && ` (${summary.osAccuracy}%)`}
            {summary.latency && ` · ${summary.latency}`}
            {summary.distance !== null && ` · ${summary.distance} hops`}
          </dd>
          {summary.flags.length > 0 && (
            <>
              <dt>Worth reviewing</dt>
              <dd style={{ color: 'var(--am)' }}>
                {summary.flags.map((f) => (
                  <div key={f}>{f}</div>
                ))}
              </dd>
            </>
          )}
          <dt>Ports</dt>
          <dd>
            {detail ? (
              <table className="tbl" style={{ marginTop: 0 }}>
                <tbody>
                  {detail.ports.map((p) => (
                    <tr key={`${p.proto}/${p.port}`} style={{ cursor: 'default' }}>
                      <td style={{ color: 'var(--cy)', width: 90 }}>
                        {p.port}/{p.proto}
                      </td>
                      <td style={{ width: 140 }}>{p.name || '?'}</td>
                      <td>{[p.product, p.version, p.extra].filter(Boolean).join(' ') || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              'loading…'
            )}
          </dd>
          {detail && detail.trace.length > 0 && (
            <>
              <dt>Path</dt>
              <dd>
                {detail.trace
                  .map((h) => `${h.ttl}. ${h.ip}${h.host ? ` (${h.host})` : ''}`)
                  .join('  →  ')}
              </dd>
            </>
          )}
          {detail && detail.scripts.length > 0 && (
            <>
              <dt>Scripts</dt>
              <dd>
                {detail.scripts.map((s) => (
                  <div key={s.id}>
                    <b>{s.id}</b>
                    <code className="cmd">{s.output}</code>
                  </div>
                ))}
              </dd>
            </>
          )}
        </dl>
      </td>
    </tr>
  );
}

function FragmentRow({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
