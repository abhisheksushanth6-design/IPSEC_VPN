import { describe, expect, it } from 'vitest';
import { screen, within } from '@testing-library/react';

import { mockBackendOffline, mockBackendOnline, renderAppAt } from './renderApp';

describe('backend state in the header', () => {
  it('reports FOUNDATION ONLINE when the backend answers', async () => {
    mockBackendOnline();
    renderAppAt('/overview');
    expect(await screen.findAllByText('FOUNDATION ONLINE')).not.toHaveLength(0);
  });

  it('reports the application mode read from the backend', async () => {
    mockBackendOnline();
    renderAppAt('/overview');
    expect(await screen.findAllByText('DEMO')).not.toHaveLength(0);
  });

  it('never claims capture or AI are running', async () => {
    mockBackendOnline();
    renderAppAt('/overview');
    await screen.findAllByText('FOUNDATION ONLINE');

    expect(screen.queryByText(/CAPTURING/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/^ACTIVE$/)).not.toBeInTheDocument();
    expect(screen.getAllByText('NOT INITIALIZED').length).toBeGreaterThanOrEqual(2);
  });

  it('reports BACKEND OFFLINE and keeps navigation usable when unreachable', async () => {
    mockBackendOffline();
    renderAppAt('/overview');

    expect(await screen.findAllByText('BACKEND OFFLINE')).not.toHaveLength(0);

    // The shell must survive an offline backend.
    const nav = screen.getByRole('navigation', { name: /main navigation/i });
    expect(within(nav).getByRole('link', { name: 'Reports' })).toBeInTheDocument();
    expect(await screen.findByRole('alert')).toHaveTextContent(/unable to connect/i);
  });
});
