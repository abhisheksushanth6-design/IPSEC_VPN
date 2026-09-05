import { describe, expect, it, beforeEach, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { mockBackendOnline, renderAppAt } from './renderApp';

/** Drive the `useMediaQuery` hook as if the viewport were compact. */
function setCompactViewport(isCompact: boolean): void {
  vi.stubGlobal(
    'matchMedia',
    vi.fn((query: string) => ({
      matches: isCompact && query.includes('max-width'),
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    })),
  );
}

describe('responsive behaviour', () => {
  beforeEach(() => {
    mockBackendOnline();
  });

  it('keeps the sidebar present and collapsible on desktop', async () => {
    setCompactViewport(false);
    renderAppAt('/overview');

    const nav = await screen.findByRole('navigation', { name: /main navigation/i });
    expect(nav).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /collapse navigation/i }),
    ).toBeInTheDocument();
  });

  it('hides the sidebar behind a menu button on compact viewports', async () => {
    setCompactViewport(true);
    renderAppAt('/overview');

    // The drawer is closed, so its contents are out of the accessibility tree.
    await waitFor(() => {
      expect(
        screen.queryByRole('navigation', { name: /main navigation/i }),
      ).not.toBeInTheDocument();
    });

    expect(screen.getByRole('button', { name: /open navigation/i })).toBeInTheDocument();
    // No desktop collapse control on compact viewports.
    expect(
      screen.queryByRole('button', { name: /collapse navigation/i }),
    ).not.toBeInTheDocument();
  });

  it('opens and closes the mobile navigation drawer', async () => {
    setCompactViewport(true);
    const user = userEvent.setup();
    renderAppAt('/overview');

    await user.click(await screen.findByRole('button', { name: /open navigation/i }));

    const nav = await screen.findByRole('navigation', { name: /main navigation/i });
    expect(within(nav).getByRole('link', { name: 'Reports' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /close navigation/i }));
    await waitFor(() => {
      expect(
        screen.queryByRole('navigation', { name: /main navigation/i }),
      ).not.toBeInTheDocument();
    });
  });

  it('closes the drawer after navigating', async () => {
    setCompactViewport(true);
    const user = userEvent.setup();
    renderAppAt('/overview');

    await user.click(await screen.findByRole('button', { name: /open navigation/i }));
    const nav = await screen.findByRole('navigation', { name: /main navigation/i });
    await user.click(within(nav).getByRole('link', { name: 'Vulnerabilities' }));

    await waitFor(() => {
      expect(
        screen.queryByRole('navigation', { name: /main navigation/i }),
      ).not.toBeInTheDocument();
    });
    expect(
      await screen.findByRole('heading', { name: /vulnerabilities/i }),
    ).toBeInTheDocument();
  });
  it.each([['desktop', false], ['compact', true]] as const)(
    'renders the feature engineering workspace on %s viewports without overflow classes',
    async (_label, compact) => {
      setCompactViewport(compact);
      const { container } = renderAppAt('/feature-engineering');

      expect(
        await screen.findByRole('heading', { name: /Feature Extraction & Engineering/i }),
      ).toBeInTheDocument();
      expect(await screen.findByRole('region', { name: /Feature Source/i })).toBeInTheDocument();

      // Wide tables scroll inside their own container; the page itself never does.
      const main = container.querySelector('#main-content');
      expect(main).not.toBeNull();
      expect(main!.className).not.toMatch(/overflow-x-(auto|scroll)/);
    },
  );
});
