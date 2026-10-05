import { useState } from 'react';
import { api, ApiError } from '../lib/api';
import { useRoute } from '../lib/router';
import { useSession } from '../store/useSession';

/** Landing page for `midden login`: the signed-in browser hands the CLI an API key. */
export function CliAuthPage() {
  const route = useRoute((s) => s.route);
  const navigate = useRoute((s) => s.navigate);
  const me = useSession((s) => s.user);
  const [done, setDone] = useState(false);
  const [error, setError] = useState('');
  const challenge = route.kind === 'cli' ? route.challenge : '';

  const allow = async (): Promise<void> => {
    setError('');
    try {
      await api('POST', '/api/auth/cli/authorize', { challenge });
      setDone(true);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not approve the CLI');
    }
  };

  return (
    <div className="overlay" style={{ alignItems: 'center' }}>
      <div className="modal narrow" data-testid="cli-auth">
        <div className="mhead">
          <h3>Midden CLI sign-in</h3>
        </div>
        <div className="mbody">
          {!challenge || done || error ? null : (
            <p style={{ marginTop: 0 }}>
              The <code>midden</code> command-line tool on this machine wants to upload scans as{' '}
              <b>{me?.displayName ?? me?.username}</b>. This creates an API key listed under your
              API keys, which you can revoke at any time.
            </p>
          )}
          {done && (
            <p style={{ marginTop: 0 }}>
              Approved — you can close this tab and return to your terminal.
            </p>
          )}
          {!done && <div className="err">{error}</div>}
        </div>
        <div className="mfoot">
          <button className="btn ghost" onClick={() => navigate({ kind: 'cases' })}>
            {done ? 'Back to Midden' : 'Cancel'}
          </button>
          <span className="sp" />
          {!done && (
            <button
              className="btn pri"
              disabled={!challenge}
              onClick={() => void allow()}
              data-testid="cli-allow"
            >
              Allow
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
