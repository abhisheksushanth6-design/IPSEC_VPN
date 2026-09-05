import { useCallback, useEffect, useReducer, useRef } from 'react';

import { NetworkError, PacketServiceError, saService } from '@/services';
import type { SAEngineStatus, SAFilters, SAPage, SASortKey, SecurityAssociation } from '@/types';
import type { PacketError } from './usePacketAnalysis';

interface State {
  status: SAEngineStatus | null; statusLoading: boolean;
  page: SAPage | null; listLoading: boolean; filters: SAFilters;
  selectedId: string | null; detail: SecurityAssociation | null; detailLoading: boolean;
  busy: 'discover' | 'clear' | null; error: PacketError;
}

type Action =
  | { type: 'status'; status: SAEngineStatus | null; loading?: boolean }
  | { type: 'page'; page: SAPage | null; loading?: boolean }
  | { type: 'filters'; filters: Partial<SAFilters>; resetPage?: boolean }
  | { type: 'toggleSort'; sort: SASortKey }
  | { type: 'select'; id: string | null }
  | { type: 'detail'; detail: SecurityAssociation | null; loading?: boolean }
  | { type: 'busy'; busy: State['busy'] }
  | { type: 'error'; error: PacketError };

export const DEFAULT_SA_FILTERS: SAFilters = { page: 1, pageSize: 25, sort: 'start_time', order: 'asc' };

const initial: State = { status: null, statusLoading: true, page: null, listLoading: false, filters: DEFAULT_SA_FILTERS, selectedId: null, detail: null, detailLoading: false, busy: null, error: null };

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case 'status': return { ...state, status: action.status, statusLoading: action.loading ?? false };
    case 'page': return { ...state, page: action.page, listLoading: action.loading ?? false };
    case 'filters': return { ...state, filters: { ...state.filters, ...action.filters, page: action.resetPage ? 1 : action.filters.page ?? state.filters.page } };
    case 'toggleSort': { const order = state.filters.sort === action.sort && state.filters.order === 'asc' ? 'desc' : 'asc'; return { ...state, filters: { ...state.filters, sort: action.sort, order, page: 1 } }; }
    case 'select': return { ...state, selectedId: action.id, detail: action.id ? state.detail : null };
    case 'detail': return { ...state, detail: action.detail, detailLoading: action.loading ?? false };
    case 'busy': return { ...state, busy: action.busy };
    case 'error': return { ...state, error: action.error };
  }
}

function toError(error: unknown): PacketError {
  if (error instanceof PacketServiceError) return { code: error.code, message: error.message };
  if (error instanceof NetworkError) return { code: 'SA_SERVICE_UNAVAILABLE', message: 'The SA lifecycle service could not be reached.' };
  return { code: 'REQUEST_FAILED', message: error instanceof Error ? error.message : 'The request failed.' };
}

export function useSALifecycle(initialSelectedId: string | null = null) {
  const [state, dispatch] = useReducer(reducer, { ...initial, selectedId: initialSelectedId });
  const listAbort = useRef<AbortController | null>(null);

  const loadStatus = useCallback(async () => {
    dispatch({ type: 'status', status: null, loading: true });
    try { dispatch({ type: 'status', status: await saService.fetchStatus() }); dispatch({ type: 'error', error: null }); }
    catch (error) { dispatch({ type: 'status', status: null }); dispatch({ type: 'error', error: toError(error) }); }
  }, []);

  const loadPage = useCallback(async (filters: SAFilters) => {
    listAbort.current?.abort();
    const controller = new AbortController(); listAbort.current = controller;
    dispatch({ type: 'page', page: null, loading: true });
    try { const page = await saService.fetchSAs(filters, controller.signal); if (!controller.signal.aborted) dispatch({ type: 'page', page }); }
    catch (error) { if (controller.signal.aborted) return; dispatch({ type: 'page', page: null }); dispatch({ type: 'error', error: toError(error) }); }
  }, []);

  useEffect(() => { void loadStatus(); }, [loadStatus]);
  useEffect(() => { if (state.status?.state === 'ACTIVE') void loadPage(state.filters); else dispatch({ type: 'page', page: null }); }, [state.status?.state, state.filters, loadPage]);
  useEffect(() => {
    if (!state.selectedId) return;
    let active = true;
    dispatch({ type: 'detail', detail: null, loading: true });
    saService.fetchSA(state.selectedId).then((detail) => { if (active) dispatch({ type: 'detail', detail }); })
      .catch((error: unknown) => { if (!active) return; dispatch({ type: 'detail', detail: null }); dispatch({ type: 'error', error: toError(error) }); });
    return () => { active = false; };
  }, [state.selectedId]);

  const run = useCallback(async (kind: NonNullable<State['busy']>, op: () => Promise<SAEngineStatus>) => {
    dispatch({ type: 'busy', busy: kind }); dispatch({ type: 'error', error: null });
    try { dispatch({ type: 'status', status: await op() }); dispatch({ type: 'select', id: null }); dispatch({ type: 'filters', filters: {}, resetPage: true }); }
    catch (error) { dispatch({ type: 'error', error: toError(error) }); }
    finally { dispatch({ type: 'busy', busy: null }); }
  }, []);

  return {
    ...state,
    discover: useCallback(() => run('discover', () => saService.discover()), [run]),
    clear: useCallback(() => run('clear', () => saService.clear()), [run]),
    refresh: useCallback(() => { void loadStatus(); }, [loadStatus]),
    setFilters: useCallback((filters: Partial<SAFilters>) => dispatch({ type: 'filters', filters, resetPage: !('page' in filters) }), []),
    setSort: useCallback((sort: SASortKey) => dispatch({ type: 'toggleSort', sort }), []),
    select: useCallback((id: string | null) => dispatch({ type: 'select', id }), []),
    dismissError: useCallback(() => dispatch({ type: 'error', error: null }), []),
  };
}

export type SAController = ReturnType<typeof useSALifecycle>;
