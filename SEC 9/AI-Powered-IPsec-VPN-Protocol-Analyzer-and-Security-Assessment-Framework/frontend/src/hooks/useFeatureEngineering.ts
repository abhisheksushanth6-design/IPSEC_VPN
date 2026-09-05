import { useCallback, useEffect, useReducer, useRef } from 'react';

import { NetworkError, PacketServiceError, featureService } from '@/services';
import type {
  FeatureEngineStatus,
  FeatureEntityList,
  FeatureEntityType,
  FeatureVector,
} from '@/types';
import type { PacketError } from './usePacketAnalysis';

interface State {
  status: FeatureEngineStatus | null;
  statusLoading: boolean;
  entityType: FeatureEntityType;
  entities: FeatureEntityList | null;
  entitiesLoading: boolean;
  selectedId: string | null;
  vector: FeatureVector | null;
  vectorLoading: boolean;
  busy: 'extract' | 'clear' | null;
  error: PacketError;
}

type Action =
  | { type: 'status'; status: FeatureEngineStatus | null; loading?: boolean }
  | { type: 'entityType'; entityType: FeatureEntityType }
  | { type: 'entities'; entities: FeatureEntityList | null; loading?: boolean }
  | { type: 'select'; id: string | null }
  | { type: 'vector'; vector: FeatureVector | null; loading?: boolean }
  | { type: 'busy'; busy: State['busy'] }
  | { type: 'error'; error: PacketError };

const initial: State = {
  status: null,
  statusLoading: true,
  entityType: 'SESSION',
  entities: null,
  entitiesLoading: false,
  selectedId: null,
  vector: null,
  vectorLoading: false,
  busy: null,
  error: null,
};

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case 'status':
      return { ...state, status: action.status, statusLoading: action.loading ?? false };
    case 'entityType':
      return {
        ...state,
        entityType: action.entityType,
        selectedId: null,
        vector: null,
        entities: null,
      };
    case 'entities':
      return { ...state, entities: action.entities, entitiesLoading: action.loading ?? false };
    case 'select':
      return { ...state, selectedId: action.id, vector: action.id ? state.vector : null };
    case 'vector':
      return { ...state, vector: action.vector, vectorLoading: action.loading ?? false };
    case 'busy':
      return { ...state, busy: action.busy };
    case 'error':
      return { ...state, error: action.error };
  }
}

function toError(error: unknown): PacketError {
  if (error instanceof PacketServiceError) return { code: error.code, message: error.message };
  if (error instanceof NetworkError) {
    return {
      code: 'FEATURE_SERVICE_UNAVAILABLE',
      message: 'The feature extraction service could not be reached.',
    };
  }
  return {
    code: 'REQUEST_FAILED',
    message: error instanceof Error ? error.message : 'The request failed.',
  };
}

/**
 * Feature engineering state. Every value shown on the page comes from the
 * backend; nothing is calculated here, so the UI cannot drift from the engine.
 */
export function useFeatureEngineering(
  initialEntityType: FeatureEntityType = 'SESSION',
  initialEntityId: string | null = null,
) {
  const [state, dispatch] = useReducer(reducer, {
    ...initial,
    entityType: initialEntityType,
    selectedId: initialEntityId,
  });
  const entitiesAbort = useRef<AbortController | null>(null);

  const loadStatus = useCallback(async () => {
    dispatch({ type: 'status', status: null, loading: true });
    try {
      dispatch({ type: 'status', status: await featureService.fetchStatus() });
      dispatch({ type: 'error', error: null });
    } catch (error) {
      dispatch({ type: 'status', status: null });
      dispatch({ type: 'error', error: toError(error) });
    }
  }, []);

  const loadEntities = useCallback(async (entityType: FeatureEntityType) => {
    entitiesAbort.current?.abort();
    const controller = new AbortController();
    entitiesAbort.current = controller;
    dispatch({ type: 'entities', entities: null, loading: true });
    try {
      const entities = await featureService.fetchEntities(entityType, controller.signal);
      if (!controller.signal.aborted) dispatch({ type: 'entities', entities });
    } catch (error) {
      if (controller.signal.aborted) return;
      dispatch({ type: 'entities', entities: null });
      dispatch({ type: 'error', error: toError(error) });
    }
  }, []);

  useEffect(() => {
    void loadStatus();
  }, [loadStatus]);

  useEffect(() => {
    void loadEntities(state.entityType);
  }, [state.entityType, state.status?.capture_id, loadEntities]);

  // A stored vector is shown as soon as an entity is selected; extraction is
  // only ever triggered by the operator pressing Extract.
  useEffect(() => {
    if (!state.selectedId) return;
    let active = true;
    dispatch({ type: 'vector', vector: null, loading: true });
    featureService
      .fetchForEntity(state.entityType, state.selectedId)
      .then((vector) => {
        if (active) dispatch({ type: 'vector', vector });
      })
      .catch((error: unknown) => {
        if (!active) return;
        dispatch({ type: 'vector', vector: null });
        // A missing vector is the normal state before extraction, not an error.
        if (error instanceof PacketServiceError && error.status === 404) return;
        dispatch({ type: 'error', error: toError(error) });
      });
    return () => {
      active = false;
    };
  }, [state.entityType, state.selectedId]);

  const extract = useCallback(async () => {
    if (!state.selectedId) return;
    dispatch({ type: 'busy', busy: 'extract' });
    dispatch({ type: 'error', error: null });
    try {
      const response = await featureService.extract(state.entityType, state.selectedId);
      dispatch({ type: 'vector', vector: response.feature_vector });
      dispatch({ type: 'status', status: await featureService.fetchStatus() });
      void loadEntities(state.entityType);
    } catch (error) {
      dispatch({ type: 'error', error: toError(error) });
    } finally {
      dispatch({ type: 'busy', busy: null });
    }
  }, [state.entityType, state.selectedId, loadEntities]);

  const clear = useCallback(async () => {
    dispatch({ type: 'busy', busy: 'clear' });
    dispatch({ type: 'error', error: null });
    try {
      dispatch({ type: 'status', status: await featureService.clear() });
      dispatch({ type: 'vector', vector: null });
      void loadEntities(state.entityType);
    } catch (error) {
      dispatch({ type: 'error', error: toError(error) });
    } finally {
      dispatch({ type: 'busy', busy: null });
    }
  }, [state.entityType, loadEntities]);

  return {
    ...state,
    extract,
    clear,
    refresh: useCallback(() => {
      void loadStatus();
      void loadEntities(state.entityType);
    }, [loadStatus, loadEntities, state.entityType]),
    setEntityType: useCallback(
      (entityType: FeatureEntityType) => dispatch({ type: 'entityType', entityType }),
      [],
    ),
    select: useCallback((id: string | null) => dispatch({ type: 'select', id }), []),
    dismissError: useCallback(() => dispatch({ type: 'error', error: null }), []),
  };
}

export type FeatureController = ReturnType<typeof useFeatureEngineering>;
