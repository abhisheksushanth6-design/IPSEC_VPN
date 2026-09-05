import { describe, expect, it, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';

import { NAVIGATION_ITEMS } from '@/config/navigation';
import { mockBackendOnline, renderAppAt } from './renderApp';

describe('routing', () => {
  beforeEach(() => {
    mockBackendOnline();
  });

  it('defines a route for every sidebar item', () => {
    expect(NAVIGATION_ITEMS).toHaveLength(13);
  });

  it.each(NAVIGATION_ITEMS.map((item) => [item.path, item.label]))(
    'renders %s without error',
    async (path, label) => {
      renderAppAt(path as string);
      await waitFor(() => {
        expect(
          screen.getAllByRole('heading', { name: new RegExp(label as string, 'i') }).length,
        ).toBeGreaterThan(0);
      });
    },
  );

  it('redirects the root path to Overview', async () => {
    renderAppAt('/');
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /^overview$/i })).toBeInTheDocument();
    });
  });

  it('shows a not-found page for an unknown route', async () => {
    renderAppAt('/no-such-page');
    expect(
      await screen.findByRole('heading', { name: /this page does not exist/i }),
    ).toBeInTheDocument();
  });
});
