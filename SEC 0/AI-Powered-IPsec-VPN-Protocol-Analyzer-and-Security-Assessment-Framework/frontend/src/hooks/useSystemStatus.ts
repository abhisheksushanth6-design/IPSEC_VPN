import { useCallback, useEffect, useState } from 'react';

import { fetchSystemStatus } from '@/services/api';
import type { SystemStatus } from '@/types';

type RequestState = 'loading' | 'ready' | 'error';

interface UseSystemStatusResult {
  state: RequestState;
  status: SystemStatus | null;
  errorMessage: string | null;
  retry: () => void;
}

/** Loads system status from the backend and exposes loading/error state. */
export function useSystemStatus(): UseSystemStatusResult {
  const [state, setState] = useState<RequestState>('loading');
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  const retry = useCallback(() => {
    setAttempt((value) => value + 1);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;

    setState('loading');
    setErrorMessage(null);

    fetchSystemStatus(controller.signal)
      .then((result) => {
        if (!active) return;
        setStatus(result);
        setState('ready');
      })
      .catch((error: unknown) => {
        if (!active || controller.signal.aborted) return;
        setErrorMessage(
          error instanceof Error ? error.message : 'Could not load system status.',
        );
        setState('error');
      });

    return () => {
      active = false;
      controller.abort();
    };
  }, [attempt]);

  return { state, status, errorMessage, retry };
}
