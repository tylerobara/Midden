import type { ReactNode } from 'react';
import { useSession } from '../store/useSession';
import { useRoute } from '../lib/router';
import { Toasts } from './Toasts';

/** Shell for non-case pages in hosted mode: brand, page title, nav, sign-out. */
export function HostedChrome({ title, children }: { title: string; children: ReactNode }) {
  const { user, logout } = useSession();
  const navigate = useRoute((s) => s.navigate);
  return (
    <div id="app">
      <header className="topbar">
        <div
          className="brand"
          style={{ cursor: 'pointer' }}
          onClick={() => navigate({ kind: 'cases' })}
        >
          <i className="dot" />
          <b>MIDDEN</b>
          <span>{title}</span>
        </div>
        <div className="caseband" />
        <div className="topact">
          <button
            className="btn ghost"
            onClick={() => navigate({ kind: 'cases' })}
            data-testid="nav-cases"
          >
            Cases
          </button>
          {user?.role === 'admin' && (
            <button
              className="btn ghost"
              onClick={() => navigate({ kind: 'users' })}
              data-testid="nav-users"
            >
              Users
            </button>
          )}
          <button className="btn ghost" onClick={() => navigate({ kind: 'password' })}>
            Password
          </button>
          <button
            className="btn ghost"
            onClick={() => navigate({ kind: 'keys' })}
            data-testid="nav-keys"
          >
            API keys
          </button>
          <button className="btn" onClick={() => void logout()} data-testid="logout">
            Sign out {user?.displayName}
          </button>
        </div>
      </header>
      <div className="split">
        <main>
          <div className="viewport">{children}</div>
        </main>
      </div>
      <Toasts />
    </div>
  );
}
