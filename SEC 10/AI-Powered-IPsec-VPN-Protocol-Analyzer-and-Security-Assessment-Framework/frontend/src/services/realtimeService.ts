import { REALTIME_RECONNECT } from '@/config/monitor';
import type { RealtimeConnectionState, RealtimeMessage } from '@/types';
import { eventStreamUrl } from './httpClient';

type StateListener = (state: RealtimeConnectionState, detail?: string) => void;
type MessageListener = (message: RealtimeMessage) => void;

/**
 * Single owner of the /ws/events connection.
 *
 * Reconnects with doubling backoff up to a fixed number of attempts, then
 * stops and reports ERROR so the user can retry deliberately. It never
 * synthesises messages: everything it emits arrived over the socket.
 */
export class RealtimeService {
  private socket: WebSocket | null = null;
  private state: RealtimeConnectionState = 'IDLE';
  private attempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private manuallyClosed = false;
  private stateListeners = new Set<StateListener>();
  private messageListeners = new Set<MessageListener>();

  getState(): RealtimeConnectionState {
    return this.state;
  }

  connect(): void {
    if (this.socket && (this.state === 'CONNECTED' || this.state === 'CONNECTING')) return;
    if (typeof WebSocket === 'undefined') {
      this.setState('ERROR', 'WebSocket is not supported in this environment.');
      return;
    }

    this.manuallyClosed = false;
    this.clearTimer();
    this.setState(this.attempts === 0 ? 'CONNECTING' : 'RECONNECTING');

    let socket: WebSocket;
    try {
      socket = new WebSocket(eventStreamUrl());
    } catch {
      this.setState('ERROR', 'The real-time endpoint address is invalid.');
      return;
    }
    this.socket = socket;

    socket.onopen = () => {
      this.attempts = 0;
      this.setState('CONNECTED');
    };

    socket.onmessage = (event: MessageEvent<string>) => {
      const parsed = parseRealtimeMessage(event.data);
      if (parsed) this.messageListeners.forEach((listener) => listener(parsed));
    };

    socket.onerror = () => {
      // The close handler that follows decides whether to retry.
    };

    socket.onclose = () => {
      this.socket = null;
      if (this.manuallyClosed) {
        this.setState('DISCONNECTED');
        return;
      }
      this.scheduleReconnect();
    };
  }

  disconnect(): void {
    this.manuallyClosed = true;
    this.clearTimer();
    this.attempts = 0;
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    this.setState('DISCONNECTED');
  }

  /** Reset the attempt counter and try again. Used by an explicit user action. */
  retry(): void {
    this.attempts = 0;
    this.connect();
  }

  onStateChange(listener: StateListener): () => void {
    this.stateListeners.add(listener);
    return () => this.stateListeners.delete(listener);
  }

  onMessage(listener: MessageListener): () => void {
    this.messageListeners.add(listener);
    return () => this.messageListeners.delete(listener);
  }

  private scheduleReconnect(): void {
    if (this.attempts >= REALTIME_RECONNECT.maxAttempts) {
      this.setState(
        'ERROR',
        `Gave up after ${REALTIME_RECONNECT.maxAttempts} reconnect attempts.`,
      );
      return;
    }
    const delay = Math.min(
      REALTIME_RECONNECT.initialDelayMs * 2 ** this.attempts,
      REALTIME_RECONNECT.maxDelayMs,
    );
    this.attempts += 1;
    this.setState('RECONNECTING', `Attempt ${this.attempts} of ${REALTIME_RECONNECT.maxAttempts}.`);
    this.reconnectTimer = setTimeout(() => this.connect(), delay);
  }

  private clearTimer(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  private setState(state: RealtimeConnectionState, detail?: string): void {
    this.state = state;
    this.stateListeners.forEach((listener) => listener(state, detail));
  }
}

/** Parse one frame. Returns null for anything that is not a typed message. */
export function parseRealtimeMessage(raw: string): RealtimeMessage | null {
  try {
    const value: unknown = JSON.parse(raw);
    if (
      typeof value === 'object' &&
      value !== null &&
      typeof (value as { type?: unknown }).type === 'string'
    ) {
      return value as RealtimeMessage;
    }
  } catch {
    // Not JSON; ignore.
  }
  return null;
}

export const realtimeService = new RealtimeService();
