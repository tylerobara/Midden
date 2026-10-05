import { useEffect, useState, type FormEvent } from 'react';
import { api, ApiError } from '../lib/api';
import { toast } from '../store/useToasts';
import { HostedChrome } from '../components/HostedChrome';

interface ApiKey {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt: string | null;
}

export function ApiKeysPage() {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [name, setName] = useState('');
  const [created, setCreated] = useState<string | null>(null);
  const [error, setError] = useState('');

  const [tick, setTick] = useState(0);
  useEffect(() => {
    let alive = true;
    api<{ tokens: ApiKey[] }>('GET', '/api/auth/tokens')
      .then((r) => alive && setKeys(r.tokens))
      .catch((err: unknown) =>
        toast(err instanceof ApiError ? err.message : 'Could not load API keys', 'bad'),
      );
    return () => {
      alive = false;
    };
  }, [tick]);
  const load = (): void => setTick((t) => t + 1);

  const create = async (e: FormEvent): Promise<void> => {
    e.preventDefault();
    setError('');
    try {
      const r = await api<ApiKey & { key: string }>('POST', '/api/auth/tokens', { name });
      setCreated(r.key);
      setName('');
      load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not create API key');
    }
  };
  const revoke = async (k: ApiKey): Promise<void> => {
    try {
      await api('DELETE', `/api/auth/tokens/${k.id}`);
      toast('API key revoked');
      load();
    } catch (err) {
      toast(err instanceof ApiError ? err.message : 'Revoke failed', 'bad');
    }
  };

  return (
    <HostedChrome title="API keys">
      <div style={{ maxWidth: 640, margin: '0 auto', padding: '1rem' }}>
        <p>
          API keys authenticate with <code>Authorization: Bearer &lt;key&gt;</code> for scripts such
          as the nmap plugin. A key acts as you, works until revoked, and is shown once.
        </p>
        {created && (
          <div className="field">
            <label htmlFor="newKey">Copy your new key now — it will not be shown again</label>
            <input id="newKey" readOnly value={created} onFocus={(e) => e.target.select()} />
          </div>
        )}
        <form
          onSubmit={(e) => void create(e)}
          style={{ display: 'flex', gap: 8, margin: '1rem 0' }}
        >
          <input
            placeholder="Key name, e.g. nmap plugin"
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={80}
            required
          />
          <button className="btn pri" type="submit" data-testid="create-key">
            Create key
          </button>
        </form>
        <div className="err">{error}</div>
        <table className="tbl">
          <thead>
            <tr>
              <th>Name</th>
              <th>Created</th>
              <th>Last used</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {keys.map((k) => (
              <tr key={k.id}>
                <td>{k.name}</td>
                <td>{new Date(k.createdAt).toLocaleString()}</td>
                <td>{k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleString() : 'never'}</td>
                <td>
                  <button className="btn ghost" onClick={() => void revoke(k)}>
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
            {keys.length === 0 && (
              <tr>
                <td colSpan={4}>No API keys yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </HostedChrome>
  );
}
