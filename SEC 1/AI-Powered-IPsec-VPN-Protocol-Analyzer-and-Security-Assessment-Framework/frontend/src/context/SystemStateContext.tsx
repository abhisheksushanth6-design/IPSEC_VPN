import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';

import { healthService, systemStatusService } from '@/services';
import type { HealthResponse, RequestState, SystemStatus } from '@/types';

interface SystemStateValue {
  state: RequestState;
  /** True only when the backend actually answered. */
  reachable: boolean;
  health: HealthResponse | null;
  status: SystemStatus | null;
  errorMessage: string | null;
  refresh: () => void;
}

const SystemStateContext = createContext<SystemStateValue | null>(null);

/**
 * Loads `/api/health` and `/api/system/status` once and shares the result
 * with the header and every page, so the shell makes one pair of requests
 * rather than one per component.
 */
export function SystemStateProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<RequestState>('loading');
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  const refresh = useCallback(() => setAttempt((value) => value + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;

    setState('loading');
    setErrorMessage(null);

    Promise.all([
      healthService.fetchHealth(controller.signal),
      systemStatusService.fetchSystemStatus(controller.signal),
    ])
      .then(([healthResult, statusResult]) => {
        if (!active) return;
        setHealth(healthResult);
        setStatus(statusResult);
        setState('ready');
      })
      .catch((error: unknown) => {
        if (!active || controller.signal.aborted) return;
        setHealth(null);
        setStatus(null);
        setErrorMessage(
          error instanceof Error
            ? error.message
            : 'The backend service is currently unavailable.',
        );
        setState('error');
      });

    return () => {
      active = false;
      controller.abort();
    };
  }, [attempt]);

  const value = useMemo<SystemStateValue>(
    () => ({
      state,
      reachable: state === 'ready',
      health,
      status,
      errorMessage,
      refresh,
    }),
    [state, health, status, errorMessage, refresh],
  );

  return (
    <SystemStateContext.Provider value={value}>{children}</SystemStateContext.Provider>
  );
}

export function useSystemState(): SystemStateValue {
  const value = useContext(SystemStateContext);
  if (!value) {
    throw new Error('useSystemState must be used inside a SystemStateProvider');
  }
  return value;
}
