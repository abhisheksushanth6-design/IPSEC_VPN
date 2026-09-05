import { describe, expect, it, beforeEach } from 'vitest';
import { screen } from '@testing-library/react';

import { mockBackendOnline, renderAppAt } from './renderApp';

const ANALYSIS_ROUTES = [
  '/vulnerabilities',
  '/risk-assessment',
  '/reports',
];

describe('module placeholders', () => {
  beforeEach(() => {
    mockBackendOnline();
  });

  it.each(ANALYSIS_ROUTES)('%s states that the module is not initialized', async (route) => {
    renderAppAt(route);
    expect(
      await screen.findByRole('heading', { name: /module not initialized/i }),
    ).toBeInTheDocument();
    expect(screen.getAllByText('NOT INITIALIZED').length).toBeGreaterThan(0);
  });
});
