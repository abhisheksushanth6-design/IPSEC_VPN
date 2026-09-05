/**
 * Append items to an array while keeping it at or under `limit`, dropping
 * the oldest. Returns a new array so React state updates are detected.
 */
export function appendBounded<T>(current: readonly T[], incoming: readonly T[], limit: number): T[] {
  if (incoming.length === 0) return current as T[];
  const merged = current.length + incoming.length <= limit
    ? [...current, ...incoming]
    : [...current, ...incoming].slice(-limit);
  return merged;
}
