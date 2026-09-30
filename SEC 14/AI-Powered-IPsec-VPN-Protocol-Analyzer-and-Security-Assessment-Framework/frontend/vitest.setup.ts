import '@testing-library/jest-dom/vitest';
import { afterEach, vi } from 'vitest';
import { cleanup } from '@testing-library/react';

import { configure } from '@testing-library/dom';

configure({ asyncUtilTimeout: 4000 });

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

// jsdom does not implement matchMedia, which the responsive hooks rely on.
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  }),
});

// Recharts' ResponsiveContainer observes its parent; jsdom has no ResizeObserver.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
Object.defineProperty(window, 'ResizeObserver', { writable: true, value: ResizeObserverStub });
