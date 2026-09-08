import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';

import {
  aiAnomalyService,
  healthService,
  packetService,
  systemStatusService,
} from '@/services';
import type {
  AIAnomalyEngineStatus,
  AnalysisStatus,
  HealthResponse,
  RequestState,
  SystemStatus,
} from '@/types';

interface SystemStateValue {
  state: RequestState;
  /** True only when the backend actually answered. */
  reachable: boolean;
  health: HealthResponse | null;
  status: SystemStatus | null;
  mlStatus: AIAnomalyEngineStatus | null;
  packetStatus: AnalysisStatus | null;
  errorMessage: string | null;
  refresh: () => void;
}

const SystemStateContext = createContext<SystemStateValue | null>(null);

/**
 * Loads system foundation state (`/api/health`, `/api/system/status`, `/api/ml/status`,
 * `/api/packets/status`) once and shares the result with the header and every page.
 */
export function SystemStateProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<RequestState>('loading');
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [mlStatus, setMlStatus] = useState<AIAnomalyEngineStatus | null>(null);
  const [packetStatus, setPacketStatus] = useState<AnalysisStatus | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  const refresh = useCallback(() => setAttempt((value) => value + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;

    setState('loading');
    setErrorMessage(null);

    Promise.allSettled([
      healthService.fetchHealth(controller.signal),
      systemStatusService.fetchSystemStatus(controller.signal),
      aiAnomalyService.getStatus(controller.signal),
      packetService.fetchStatus(controller.signal),
    ])
      .then(([healthRes, statusRes, mlRes, packetRes]) => {
        if (!active) return;
        const h = healthRes.status === 'fulfilled' ? healthRes.value : null;
        const s = statusRes.status === 'fulfilled' ? statusRes.value : null;
        const ml = mlRes.status === 'fulfilled' ? mlRes.value : null;
        const pkt = packetRes.status === 'fulfilled' ? packetRes.value : null;

        setHealth(h);
        setStatus(s);
        setMlStatus(ml);
        setPacketStatus(pkt);

        if (h || s) {
          setState('ready');
        } else {
          setErrorMessage('The backend service is currently unavailable.');
          setState('error');
        }
      })
      .catch((error: unknown) => {
        if (!active || controller.signal.aborted) return;
        setHealth(null);
        setStatus(null);
        setMlStatus(null);
        setPacketStatus(null);
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
      mlStatus,
      packetStatus,
      errorMessage,
      refresh,
    }),
    [state, health, status, mlStatus, packetStatus, errorMessage, refresh],
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
