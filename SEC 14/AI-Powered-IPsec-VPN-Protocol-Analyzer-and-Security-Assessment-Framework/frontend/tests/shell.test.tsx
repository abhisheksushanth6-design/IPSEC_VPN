import { describe, expect, it, beforeEach } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { NAVIGATION_ITEMS } from '@/config/navigation';
import { PROJECT_NAME } from '@/config/branding';
import { mockBackendOnline, renderAppAt } from './renderApp';

describe('application shell', () => {
  beforeEach(() => {
    mockBackendOnline();
  });

  it('shows the full official project name in the header', async () => {
    renderAppAt('/overview');
    expect(await screen.findAllByText(PROJECT_NAME)).not.toHaveLength(0);
  });

  it('renders every navigation destination in the sidebar', async () => {
    renderAppAt('/overview');
    const nav = await screen.findByRole('navigation', { name: /main navigation/i });

    for (const item of NAVIGATION_ITEMS) {
      expect(within(nav).getByRole('link', { name: item.label })).toHaveAttribute(
        'href',
        item.path,
      );
    }
  });

  it('marks the current route as active', async () => {
    renderAppAt('/vulnerabilities');
    const nav = await screen.findByRole('navigation', { name: /main navigation/i });
    const link = within(nav).getByRole('link', { name: 'Security Assessment' });
    expect(link).toHaveAttribute('aria-current', 'page');
  });

  it('provides a skip link to the main content', async () => {
    renderAppAt('/overview');
    expect(
      await screen.findByRole('link', { name: /skip to main content/i }),
    ).toBeInTheDocument();
  });

  it('opens the notifications panel and reports that none exist', async () => {
    const user = userEvent.setup();
    renderAppAt('/overview');

    await user.click(await screen.findByRole('button', { name: /notifications/i }));
    const panel = await screen.findByRole('dialog', { name: /notifications/i });
    expect(within(panel).getByText(/no new notifications/i)).toBeInTheDocument();
  });

  it('collapses and expands the sidebar', async () => {
    const user = userEvent.setup();
    renderAppAt('/overview');

    const collapse = await screen.findByRole('button', { name: /collapse navigation/i });
    expect(collapse).toHaveAttribute('aria-expanded', 'true');

    await user.click(collapse);
    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: /expand navigation/i }),
      ).toHaveAttribute('aria-expanded', 'false');
    });
  });
});
