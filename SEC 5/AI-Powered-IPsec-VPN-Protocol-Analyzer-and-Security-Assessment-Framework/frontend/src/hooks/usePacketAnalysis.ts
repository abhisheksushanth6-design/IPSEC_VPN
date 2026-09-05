import { useCallback, useEffect, useReducer, useRef } from 'react';

import { packetService, PacketServiceError, NetworkError } from '@/services';
import type {
  AnalysisStatus,
  PacketAnalysisResult,
  PacketPage,
  PacketQuery,
  PacketSortKey,
} from '@/types';

export type PacketError = { code: string; message: string } | null;

interface State {
  status: AnalysisStatus | null;
  statusLoading: boolean;
  page: PacketPage | null;
  listLoading: boolean;
  query: PacketQuery;
  selectedId: string | null;
  detail: PacketAnalysisResult | null;
  detailLoading: boolean;
  busy: 'upload' | 'analyze' | 'clear' | null;
  error: PacketError;
}

type Action =
  | { type: 'status'; status: AnalysisStatus | null; loading?: boolean }
  | { type: 'page'; page: PacketPage | null; loading?: boolean }
  | { type: 'query'; query: Partial<PacketQuery>; resetPage?: boolean }
  | { type: 'toggleSort'; sort: PacketSortKey }
  | { type: 'select'; id: string | null }
  | { type: 'detail'; detail: PacketAnalysisResult | null; loading?: boolean }
  | { type: 'busy'; busy: State['busy'] }
  | { type: 'error'; error: PacketError };

export const DEFAULT_QUERY: PacketQuery = {
  page: 1,
  pageSize: 50,
  ipsec: 'ALL',
  sort: 'number',
  order: 'asc',
};

const initial: State = {
  status: null,
  statusLoading: true,
  page: null,
  listLoading: false,
  query: DEFAULT_QUERY,
  selectedId: null,
  detail: null,
  detailLoading: false,
  busy: null,
  error: null,
};

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case 'status':
      return { ...state, status: action.status, statusLoading: action.loading ?? false };
    case 'page':
      return { ...state, page: action.page, listLoading: action.loading ?? false };
    case 'query':
      return { ...state, query: { ...state.query, ...action.query, page: action.resetPage ? 1 : action.query.page ?? state.query.page } };
    case 'toggleSort': {
      // Decided against current state inside the reducer, so rapid clicks cannot read a stale order.
      const order = state.query.sort === action.sort && state.query.order === 'asc' ? 'desc' : 'asc';
      return { ...state, query: { ...state.query, sort: action.sort, order, page: 1 } };
    }
    case 'select':
      return { ...state, selectedId: action.id, detail: action.id ? state.detail : null };
    case 'detail':
      return { ...state, detail: action.detail, detailLoading: action.loading ?? false };
    case 'busy':
      return { ...state, busy: action.busy };
    case 'error':
      return { ...state, error: action.error };
  }
}

function toError(error: unknown): PacketError {
  if (error instanceof PacketServiceError) return { code: error.code, message: error.message };
  if (error instanceof NetworkError) return { code: 'ANALYSIS_SERVICE_UNAVAILABLE', message: 'The analysis service could not be reached.' };
  if (error instanceof Error) return { code: 'REQUEST_FAILED', message: error.message };
  return { code: 'REQUEST_FAILED', message: 'The request failed.' };
}

/**
 * All packet-analysis data access for the page. Components receive state and
 * callbacks; none of them call the service directly.
 */
export function usePacketAnalysis() {
  const [state, dispatch] = useReducer(reducer, initial);
  const listAbort = useRef<AbortController | null>(null);

  const loadStatus = useCallback(async () => {
    dispatch({ type: 'status', status: null, loading: true });
    try {
      dispatch({ type: 'status', status: await packetService.fetchStatus() });
      dispatch({ type: 'error', error: null });
    } catch (error) {
      dispatch({ type: 'status', status: null });
      dispatch({ type: 'error', error: toError(error) });
    }
  }, []);

  const loadPage = useCallback(async (query: PacketQuery) => {
    listAbort.current?.abort();
    const controller = new AbortController();
    listAbort.current = controller;
    dispatch({ type: 'page', page: null, loading: true });
    try {
      const page = await packetService.fetchPackets(query, controller.signal);
      if (!controller.signal.aborted) dispatch({ type: 'page', page });
    } catch (error) {
      if (controller.signal.aborted) return;
      dispatch({ type: 'page', page: null });
      dispatch({ type: 'error', error: toError(error) });
    }
  }, []);

  useEffect(() => {
    void loadStatus();
  }, [loadStatus]);

  useEffect(() => {
    if (state.status?.state === 'COMPLETED') void loadPage(state.query);
    else dispatch({ type: 'page', page: null });
  }, [state.status?.state, state.query, loadPage]);

  useEffect(() => {
    if (!state.selectedId) return;
    let active = true;
    dispatch({ type: 'detail', detail: null, loading: true });
    packetService
      .fetchPacket(state.selectedId)
      .then((detail) => { if (active) dispatch({ type: 'detail', detail }); })
      .catch((error: unknown) => {
        if (!active) return;
        dispatch({ type: 'detail', detail: null });
        dispatch({ type: 'error', error: toError(error) });
      });
    return () => { active = false; };
  }, [state.selectedId]);

  const run = useCallback(async (kind: NonNullable<State['busy']>, op: () => Promise<AnalysisStatus>) => {
    dispatch({ type: 'busy', busy: kind });
    dispatch({ type: 'error', error: null });
    try {
      const status = await op();
      dispatch({ type: 'status', status });
      dispatch({ type: 'select', id: null });
      dispatch({ type: 'query', query: {}, resetPage: true });
    } catch (error) {
      dispatch({ type: 'error', error: toError(error) });
    } finally {
      dispatch({ type: 'busy', busy: null });
    }
  }, []);

  const upload = useCallback((file: File) => run('upload', () => packetService.uploadCapture(file)), [run]);
  const analyze = useCallback(() => run('analyze', () => packetService.analyze()), [run]);
  const clear = useCallback(() => run('clear', () => packetService.clear()), [run]);
  const refresh = useCallback(() => { void loadStatus(); }, [loadStatus]);

  const setQuery = useCallback((query: Partial<PacketQuery>) => dispatch({ type: 'query', query, resetPage: !('page' in query) }), []);
  const setSort = useCallback((sort: PacketSortKey) => dispatch({ type: 'toggleSort', sort }), []);
  const select = useCallback((id: string | null) => dispatch({ type: 'select', id }), []);
  const dismissError = useCallback(() => dispatch({ type: 'error', error: null }), []);

  return { ...state, upload, analyze, clear, refresh, setQuery, setSort, select, dismissError };
}

export type PacketAnalysisController = ReturnType<typeof usePacketAnalysis>;
