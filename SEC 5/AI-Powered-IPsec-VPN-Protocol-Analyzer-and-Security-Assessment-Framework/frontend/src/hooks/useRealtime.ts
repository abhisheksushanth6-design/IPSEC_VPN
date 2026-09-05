import { useCallback, useEffect, useRef, useState } from 'react';

import { MAX_SYSTEM_ACTIVITY, MAX_VISIBLE_EVENTS } from '@/config/monitor';
import { realtimeService } from '@/services';
import { appendBounded } from '@/utils/boundedBuffer';
import type {
  RealtimeConnectionState,
  RealtimeMessage,
  SystemActivityEvent,
  SystemActivityType,
} from '@/types';

interface UseRealtimeResult {
  connectionState: RealtimeConnectionState;
  connectionDetail: string | null;
  /** Typed frames received over the socket, newest last, bounded. */
  messages: RealtimeMessage[];
  /** Connection lifecycle only — every entry is a real socket transition. */
  activity: SystemActivityEvent[];
  retry: () => void;
}

let activitySequence = 0;

function activityFor(state: RealtimeConnectionState, detail?: string): SystemActivityEvent | null {
  const map: Partial<Record<RealtimeConnectionState, SystemActivityType>> = {
    CONNECTED: 'Realtime Connected',
    DISCONNECTED: 'Realtime Disconnected',
    ERROR: 'Realtime Error',
  };
  const type = map[state];
  if (!type) return null;
  activitySequence += 1;
  return {
    id: `activity-${activitySequence}`,
    timestamp: new Date().toISOString(),
    type,
    detail: detail ?? `/ws/events ${state.toLowerCase()}`,
  };
}

/**
 * Subscribe a page to the real-time channel. Connects on mount, disconnects
 * on unmount, and keeps bounded buffers so the DOM cannot grow unbounded.
 */
export function useRealtime(): UseRealtimeResult {
  const [connectionState, setConnectionState] = useState<RealtimeConnectionState>(
    realtimeService.getState(),
  );
  const [connectionDetail, setConnectionDetail] = useState<string | null>(null);
  const [messages, setMessages] = useState<RealtimeMessage[]>([]);
  const [activity, setActivity] = useState<SystemActivityEvent[]>([]);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;

    const offState = realtimeService.onStateChange((state, detail) => {
      if (!mounted.current) return;
      setConnectionState(state);
      setConnectionDetail(detail ?? null);
      const entry = activityFor(state, detail);
      if (entry) setActivity((current) => appendBounded(current, [entry], MAX_SYSTEM_ACTIVITY));
    });

    const offMessage = realtimeService.onMessage((message) => {
      if (!mounted.current) return;
      setMessages((current) => appendBounded(current, [message], MAX_VISIBLE_EVENTS));
    });

    realtimeService.connect();

    return () => {
      mounted.current = false;
      offState();
      offMessage();
      realtimeService.disconnect();
    };
  }, []);

  const retry = useCallback(() => realtimeService.retry(), []);

  return { connectionState, connectionDetail, messages, activity, retry };
}
