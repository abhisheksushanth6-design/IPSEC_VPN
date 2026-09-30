import { describe, expect, it, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { mockBackendOnline, renderAppAt } from './renderApp';

describe('Dark Mode / Light Mode Theme System', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute('data-theme');
    document.documentElement.className = '';
    mockBackendOnline();
  });

  it('defaults to Light Mode on initial load when no stored preference exists', async () => {
    renderAppAt('/overview');

    const toggle = await screen.findByTestId('theme-toggle');
    expect(toggle).toBeInTheDocument();
    expect(toggle).toHaveAttribute('aria-label', 'Switch to dark mode');
    expect(screen.getByText('Currently Light Mode')).toBeInTheDocument();
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    expect(document.documentElement.classList.contains('dark')).toBe(false);
  });

  it('switches between Light Mode and Dark Mode upon clicking the theme toggle button', async () => {
    const user = userEvent.setup();
    renderAppAt('/overview');

    const toggle = await screen.findByTestId('theme-toggle');
    expect(toggle).toHaveAttribute('aria-label', 'Switch to dark mode');

    // Click to switch to dark mode
    await user.click(toggle);

    await waitFor(() => {
      expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
      expect(document.documentElement.classList.contains('dark')).toBe(true);
      expect(toggle).toHaveAttribute('aria-label', 'Switch to light mode');
      expect(screen.getByText('Currently Dark Mode')).toBeInTheDocument();
    });

    // Check localStorage persistence
    expect(localStorage.getItem('ipsec_vpn_theme')).toBe('dark');

    // Click to switch back to light mode
    await user.click(toggle);

    await waitFor(() => {
      expect(document.documentElement.getAttribute('data-theme')).toBe('light');
      expect(document.documentElement.classList.contains('dark')).toBe(false);
      expect(toggle).toHaveAttribute('aria-label', 'Switch to dark mode');
      expect(screen.getByText('Currently Light Mode')).toBeInTheDocument();
    });

    expect(localStorage.getItem('ipsec_vpn_theme')).toBe('light');
  });

  it('restores Dark Mode on load when saved in localStorage', async () => {
    localStorage.setItem('ipsec_vpn_theme', 'dark');
    renderAppAt('/overview');

    const toggle = await screen.findByTestId('theme-toggle');
    expect(toggle).toBeInTheDocument();

    await waitFor(() => {
      expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
      expect(document.documentElement.classList.contains('dark')).toBe(true);
      expect(toggle).toHaveAttribute('aria-label', 'Switch to light mode');
    });
  });

  it('provides an Appearance & Theme panel in the Settings page', async () => {
    const user = userEvent.setup();
    renderAppAt('/settings');

    // Wait for lazy-loaded route to resolve
    await screen.findByText('System Settings');

    const lightOption = await screen.findByTestId('settings-theme-light');
    const darkOption = await screen.findByTestId('settings-theme-dark');

    expect(lightOption).toBeInTheDocument();
    expect(darkOption).toBeInTheDocument();
    expect(lightOption).toHaveAttribute('aria-pressed', 'true');
    expect(darkOption).toHaveAttribute('aria-pressed', 'false');

    // Click Dark Mode in Settings
    await user.click(darkOption);

    await waitFor(() => {
      expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
      expect(document.documentElement.classList.contains('dark')).toBe(true);
      expect(darkOption).toHaveAttribute('aria-pressed', 'true');
      expect(lightOption).toHaveAttribute('aria-pressed', 'false');
    });

    expect(localStorage.getItem('ipsec_vpn_theme')).toBe('dark');
  });
});
