import { describe, expect, it } from 'vitest';

import { RealtimeService } from '@/services';

/**
 * Integration check against a real running backend. Skipped unless
 * LIVE_BACKEND=1, so CI never depends on a server being up.
 */
const live = process.env.LIVE_BACKEND === '1';

describe.skipIf(!live)('realtime service against the live backend', () => {
  it('connects to /ws/events and receives the handshake frame', async () => {
    const service = new RealtimeService();
    const states: string[] = [];
    const messages: unknown[] = [];
    service.onStateChange((s) => states.push(s));
    service.onMessage((m) => messages.push(m));

    service.connect();
    await new Promise((resolve) => setTimeout(resolve, 1500));
    service.disconnect();

    expect(states).toContain('CONNECTING');
    expect(states).toContain('CONNECTED');
    expect(messages).toHaveLength(1);
    expect(messages[0]).toMatchObject({ type: 'connection.established' });
    expect(states[states.length - 1]).toBe('DISCONNECTED');
  });
});
