import { useCallback, useEffect, useReducer, useRef } from 'react';

import { NetworkError, PacketServiceError, sessionService } from '@/services';
import type { IPsecSession, SessionEngineStatus, SessionFilters, SessionPage, SessionSortKey } from '@/types';
import type { PacketError } from './usePacketAnalysis';

interface State {
  status: SessionEngineStatus | null;
  statusLoading: boolean;
  page: SessionPage | null;
  listLoading: boolean;
  filters: SessionFilters;
  selectedId: string | null;
  detail: IPsecSession | null;
  detailLoading: boolean;
  busy: 'discover' | 'clear' | null;
  error: PacketError;
}

type Action =
  | { type: 'status'; status: SessionEngineStatus | null; loading?: boolean }
  | { type: 'page'; page: SessionPage | null; loading?: boolean }
  | { type: 'filters'; filters: Partial<SessionFilters>; resetPage?: boolean }
  | { type: 'toggleSort'; sort: SessionSortKey }
  | { type: 'select'; id: string | null }
  | { type: 'detail'; detail: IPsecSession | null; loading?: boolean }
  | { type: 'busy'; busy: State['busy'] }
  | { type: 'error'; error: PacketError };

export const DEFAULT_SESSION_FILTERS: SessionFilters = { page: 1, pageSize: 25, sort: 'start_time', order: 'asc' };

const initial: State = {
  status: null, statusLoading: true, page: null, listLoading: false, filters: DEFAULT_SESSION_FILTERS,
  selectedId: null, detail: null, detailLoading: false, busy: null, error: null,
};

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case 'status': return { ...state, status: action.status, statusLoading: action.loading ?? false };
    case 'page': return { ...state, page: action.page, listLoading: action.loading ?? false };
    case 'filters': return { ...state, filters: { ...state.filters, ...action.filters, page: action.resetPage ? 1 : action.filters.page ?? state.filters.page } };
    case 'toggleSort': {
      const order = state.filters.sort === action.sort && state.filters.order === 'asc' ? 'desc' : 'asc';
      return { ...state, filters: { ...state.filters, sort: action.sort, order, page: 1 } };
    }
    case 'select': return { ...state, selectedId: action.id, detail: action.id ? state.detail : null };
    case 'detail': return { ...state, detail: action.detail, detailLoading: action.loading ?? false };
    case 'busy': return { ...state, busy: action.busy };
    case 'error': return { ...state, error: action.error };
  }
}

function toError(error: unknown): PacketError {
  if (error instanceof PacketServiceError) return { code: error.code, message: error.message };
  if (error instanceof NetworkError) return { code: 'SESSION_SERVICE_UNAVAILABLE', message: 'The session service could not be reached.' };
  return { code: 'REQUEST_FAILED', message: error instanceof Error ? error.message : 'The request failed.' };
}

/** All session data access for the page; components never call the service directly. */
export function useIPsecSessions(initialSelectedId: string | null = null) {
  const [state, dispatch] = useReducer(reducer, { ...initial, selectedId: initialSelectedId });
  const listAbort = useRef<AbortController | null>(null);

  const loadStatus = useCallback(async () => {
    dispatch({ type: 'status', status: null, loading: true });
    try {
      dispatch({ type: 'status', status: await sessionService.fetchStatus() });
      dispatch({ type: 'error', error: null });
    } catch (error) {
      dispatch({ type: 'status', status: null });
      dispatch({ type: 'error', error: toError(error) });
    }
  }, []);

  const loadPage = useCallback(async (filters: SessionFilters) => {
    listAbort.current?.abort();
    const controller = new AbortController();
    listAbort.current = controller;
    dispatch({ type: 'page', page: null, loading: true });
    try {
      const page = await sessionService.fetchSessions(filters, controller.signal);
      if (!controller.signal.aborted) dispatch({ type: 'page', page });
    } catch (error) {
      if (controller.signal.aborted) return;
      dispatch({ type: 'page', page: null });
      dispatch({ type: 'error', error: toError(error) });
    }
  }, []);

  useEffect(() => { void loadStatus(); }, [loadStatus]);

  useEffect(() => {
    if (state.status?.state === 'AVAILABLE') void loadPage(state.filters);
    else dispatch({ type: 'page', page: null });
  }, [state.status?.state, state.filters, loadPage]);

  useEffect(() => {
    if (!state.selectedId) return;
    let active = true;
    dispatch({ type: 'detail', detail: null, loading: true });
    sessionService.fetchSession(state.selectedId)
      .then((detail) => { if (active) dispatch({ type: 'detail', detail }); })
      .catch((error: unknown) => {
        if (!active) return;
        dispatch({ type: 'detail', detail: null });
        dispatch({ type: 'error', error: toError(error) });
      });
    return () => { active = false; };
  }, [state.selectedId]);

  const run = useCallback(async (kind: NonNullable<State['busy']>, op: () => Promise<SessionEngineStatus>) => {
    dispatch({ type: 'busy', busy: kind });
    dispatch({ type: 'error', error: null });
    try {
      dispatch({ type: 'status', status: await op() });
      dispatch({ type: 'select', id: null });
      dispatch({ type: 'filters', filters: {}, resetPage: true });
    } catch (error) {
      dispatch({ type: 'error', error: toError(error) });
    } finally {
      dispatch({ type: 'busy', busy: null });
    }
  }, []);

  const discover = useCallback(() => run('discover', () => sessionService.discover()), [run]);
  const clear = useCallback(() => run('clear', () => sessionService.clear()), [run]);
  const refresh = useCallback(() => { void loadStatus(); }, [loadStatus]);
  const setFilters = useCallback((filters: Partial<SessionFilters>) => dispatch({ type: 'filters', filters, resetPage: !('page' in filters) }), []);
  const setSort = useCallback((sort: SessionSortKey) => dispatch({ type: 'toggleSort', sort }), []);
  const select = useCallback((id: string | null) => dispatch({ type: 'select', id }), []);
  const dismissError = useCallback(() => dispatch({ type: 'error', error: null }), []);

  return { ...state, discover, clear, refresh, setFilters, setSort, select, dismissError };
}

export type SessionController = ReturnType<typeof useIPsecSessions>;
