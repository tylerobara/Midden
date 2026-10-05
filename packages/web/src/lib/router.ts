import { useEffect } from 'react';
import { create } from 'zustand';
import { useUiStore, VIEW_IDS, type ViewId } from '../store/useUiStore';

export type CaseView = ViewId | 'history';
export const CASE_VIEWS: CaseView[] = [...VIEW_IDS, 'history'];

export type Route =
  | { kind: 'login' }
  | { kind: 'cases' }
  | { kind: 'users' }
  | { kind: 'password' }
  | { kind: 'keys' }
  | { kind: 'case'; caseId: string; view: CaseView }
  | { kind: 'standalone'; view: ViewId };

const isView = (v: string | undefined): v is ViewId => !!v && (VIEW_IDS as string[]).includes(v);
const isCaseView = (v: string | undefined): v is CaseView =>
  !!v && (CASE_VIEWS as string[]).includes(v);

/** Hash routes work from file:// too. Hosted: #/cases, #/c/<id>/<view>, #/users, #/login. Standalone: #/<view>. */
export function parseRoute(hash: string, mode: 'server' | 'standalone'): Route {
  const parts = hash.replace(/^#\/?/, '').split('/').filter(Boolean);
  if (mode === 'standalone')
    return { kind: 'standalone', view: isView(parts[0]) ? parts[0] : 'graph' };
  switch (parts[0]) {
    case 'login':
      return { kind: 'login' };
    case 'users':
      return { kind: 'users' };
    case 'password':
      return { kind: 'password' };
    case 'keys':
      return { kind: 'keys' };
    case 'c': {
      const caseId = parts[1];
      if (!caseId) return { kind: 'cases' };
      return { kind: 'case', caseId, view: isCaseView(parts[2]) ? parts[2] : 'graph' };
    }
    default:
      return { kind: 'cases' };
  }
}

export function routeHash(r: Route): string {
  switch (r.kind) {
    case 'login':
      return '#/login';
    case 'cases':
      return '#/cases';
    case 'users':
      return '#/users';
    case 'password':
      return '#/password';
    case 'keys':
      return '#/keys';
    case 'case':
      return `#/c/${r.caseId}/${r.view}`;
    case 'standalone':
      return `#/${r.view}`;
  }
}

/** Back-compat helper used by tests: which UI view a hash points at in standalone mode. */
export function parseHash(hash: string): ViewId | null {
  const m = /^#\/?([a-z]+)/.exec(hash);
  const v = m?.[1];
  return isView(v) ? v : null;
}

interface RouteState {
  route: Route;
  navigate(r: Route): void;
}

const MODE = __MIDDEN_MODE__ === 'standalone' ? 'standalone' : 'server';

export const useRoute = create<RouteState>((set) => ({
  route: parseRoute(typeof location !== 'undefined' ? location.hash : '', MODE),
  navigate(r) {
    const h = routeHash(r);
    if (location.hash !== h) location.hash = h;
    set({ route: { ...r } });
  },
}));

/** Keeps the route store and the UI view in sync with the address bar. */
export function useHashRouter(): void {
  const navigate = useRoute((s) => s.navigate);
  const setView = useUiStore((s) => s.setView);
  useEffect(() => {
    const sync = (): void => {
      const r = parseRoute(location.hash, MODE);
      useRoute.setState({ route: r });
      if (r.kind === 'standalone') setView(r.view);
      if (r.kind === 'case' && r.view !== 'history') setView(r.view);
    };
    sync();
    window.addEventListener('hashchange', sync);
    return () => window.removeEventListener('hashchange', sync);
  }, [navigate, setView]);
}

/** Navigate to a view within the current context (standalone view or case view). */
export function goToView(view: CaseView): void {
  const { route, navigate } = useRoute.getState();
  if (route.kind === 'case') navigate({ ...route, view });
  else if (route.kind === 'standalone' && view !== 'history')
    navigate({ kind: 'standalone', view });
}
