import { useEffect, useRef } from 'react';
import { emptyState } from '@midden/core';
import { TopBar } from './components/TopBar';
import { Sidebar } from './components/Sidebar';
import { Tabs } from './components/Tabs';
import { Toasts } from './components/Toasts';
import { ModalRoot } from './components/ModalRoot';
import { ConnectionBanner } from './components/ConnectionBanner';
import { GraphView } from './views/GraphView';
import { TimelineView } from './views/TimelineView';
import { HostsView } from './views/HostsView';
import { IndicatorsView } from './views/IndicatorsView';
import { MatrixView } from './views/MatrixView';
import { ReportView } from './views/ReportView';
import { ScansView } from './views/ScansView';
import { MapView } from './views/MapView';
import { BuilderView } from './views/BuilderView';
import { HistoryView } from './views/HistoryView';
import { useUiStore } from './store/useUiStore';
import { useCaseStore } from './store/useCaseStore';
import { useSession } from './store/useSession';
import { ServerStore } from './store/ServerStore';
import { useTerrain } from './store/useTerrain';
import { MemoryTerrain, ServerTerrain } from './lib/terrain';
import { LocalFileStore } from './store/LocalFileStore';
import { restoreAutosave, startAutosave } from './lib/autosave';
import { useHashRouter, useRoute } from './lib/router';
import { useKeyboard, useUnloadGuard } from './lib/useKeyboard';
import { runWorkerSelfTest } from './workers/nmap';
import { api, type CaseAccess } from './lib/api';
import { LoginPage } from './pages/LoginPage';
import { CasesPage } from './pages/CasesPage';
import { UsersPage } from './pages/UsersPage';
import { ApiKeysPage } from './pages/ApiKeysPage';
import { ChangePasswordPage } from './pages/ChangePasswordPage';
import { toast } from './store/useToasts';

export function App() {
  useHashRouter();
  useKeyboard();
  useUnloadGuard();
  useEffect(() => {
    document.documentElement.dataset.mode = __MIDDEN_MODE__;
    document.documentElement.dataset.version = __MIDDEN_VERSION__;
    if (__MIDDEN_MODE__ === 'standalone') runWorkerSelfTest();
  }, []);
  return __MIDDEN_MODE__ === 'standalone' ? <StandaloneApp /> : <HostedApp />;
}

/** Restore the last session's work from this browser, then keep saving it as it changes. */
function StandaloneApp() {
  useEffect(() => {
    let stop: (() => void) | null = null;
    let cancelled = false;
    void restoreAutosave().then((restored) => {
      if (cancelled) return;
      if (restored) {
        const when = restored.savedAt ? new Date(restored.savedAt).toLocaleString() : 'earlier';
        toast(`Restored your work from ${when} (${restored.events} events)`);
      }
      stop = startAutosave();
    });
    return () => {
      cancelled = true;
      stop?.();
    };
  }, []);
  return <CaseShell />;
}

function HostedApp() {
  const { status, load, mustChangePassword } = useSession();
  const route = useRoute((s) => s.route);
  useEffect(() => {
    if (status === 'unknown') void load();
  }, [status, load]);
  if (status === 'unknown') return <div className="empty">Loading…</div>;
  if (status === 'anon') return <LoginPage />;
  if (mustChangePassword || route.kind === 'password') return <ChangePasswordPage />;
  switch (route.kind) {
    case 'users':
      return <UsersPage />;
    case 'keys':
      return <ApiKeysPage />;
    case 'case':
      return <HostedCase caseId={route.caseId} history={route.view === 'history'} />;
    default:
      return <CasesPage />;
  }
}

/** Mounts a ServerStore for the routed case and keeps presence in sync. */
function HostedCase({ caseId, history }: { caseId: string; history: boolean }) {
  const user = useSession((s) => s.user);
  const attachAdapter = useCaseStore((s) => s.attachAdapter);
  const adapter = useCaseStore((s) => s.adapter);
  const view = useUiStore((s) => s.view);
  const sel = useUiStore((s) => s.sel);
  const modal = useUiStore((s) => s.modal);
  const navigate = useRoute((s) => s.navigate);

  useEffect(() => {
    if (!user) return;
    let cancelled = false;
    void api<{ case: { access: CaseAccess; name: string } }>('GET', `/api/cases/${caseId}`)
      .then((r) => {
        if (cancelled) return;
        attachAdapter(new ServerStore(caseId, { id: user.id, name: user.displayName }), {
          caseId,
          me: { id: user.id, name: user.displayName },
          access: r.case.access,
        });
        useTerrain.getState().setStore(new ServerTerrain(caseId, r.case.access.edit));
      })
      .catch(() => {
        toast('Case not found', 'bad');
        navigate({ kind: 'cases' });
      });
    return () => {
      cancelled = true;
      attachAdapter(new LocalFileStore(emptyState()));
      useTerrain.getState().setStore(new MemoryTerrain());
    };
  }, [caseId, user, attachAdapter, navigate]);

  useEffect(() => {
    if (adapter instanceof ServerStore) {
      const editingId =
        modal.kind === 'event' || modal.kind === 'host' ? (modal.id ?? undefined) : undefined;
      adapter.presence(history ? 'history' : view, sel ?? undefined, editingId);
    }
  }, [adapter, view, sel, modal, history]);

  return <CaseShell history={history} />;
}

export function CaseShell({ history = false }: { history?: boolean }) {
  const view = useUiStore((s) => s.view);
  const sidebarOpen = useUiStore((s) => s.sidebarOpen);
  const viewport = useRef<HTMLDivElement>(null);
  useEffect(() => {
    document.body.classList.toggle('sbopen', sidebarOpen);
  }, [sidebarOpen]);
  useEffect(() => {
    if (viewport.current) viewport.current.scrollTop = 0;
  }, [view, history]);
  const current = history ? 'history' : view;

  return (
    <div id="app">
      <TopBar />
      <div className="split">
        <Sidebar />
        <main>
          <Tabs />
          <ConnectionBanner />
          <div className="viewport" id="viewport" ref={viewport}>
            <section
              className={'view on' + (current === 'graph' ? ' flush' : '')}
              data-testid={`view-${current}`}
            >
              {current === 'graph' && <GraphView />}
              {current === 'timeline' && <TimelineView scrollRef={viewport} />}
              {current === 'hosts' && <HostsView />}
              {current === 'pivot' && <IndicatorsView />}
              {current === 'matrix' && <MatrixView />}
              {current === 'scans' && <ScansView />}
              {current === 'map' && <MapView />}
              {current === 'builder' && <BuilderView />}
              {current === 'report' && <ReportView />}
              {current === 'history' && <HistoryView />}
            </section>
          </div>
        </main>
      </div>
      <ModalRoot />
      <Toasts />
    </div>
  );
}
