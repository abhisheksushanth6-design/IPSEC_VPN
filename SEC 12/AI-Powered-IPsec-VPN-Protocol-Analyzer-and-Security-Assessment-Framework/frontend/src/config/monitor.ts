/** Tunables for the Live Monitor. Adjust here, not in components. */

/** Upper bound on rows kept in memory and rendered for any live list. */
export const MAX_VISIBLE_EVENTS = 500;
export const MAX_VISIBLE_PACKETS = 1000;
export const MAX_SYSTEM_ACTIVITY = 100;

/** Reconnect policy for /ws/events. Backoff doubles up to the cap; then stops. */
export const REALTIME_RECONNECT = {
  initialDelayMs: 1_000,
  maxDelayMs: 30_000,
  maxAttempts: 5,
} as const;
