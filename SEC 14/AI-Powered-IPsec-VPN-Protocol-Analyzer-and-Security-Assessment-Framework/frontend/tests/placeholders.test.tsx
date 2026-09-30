import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { Shield } from 'lucide-react';

import { ModulePlaceholder } from '@/components/ui/ModulePlaceholder';

describe('module placeholders', () => {
  it('renders module not initialized state when instantiated', () => {
    render(
      <MemoryRouter>
        <ModulePlaceholder
          title="Test Module"
          description="Test description for placeholder module"
          icon={Shield}
        />
      </MemoryRouter>
    );

    expect(
      screen.getByRole('heading', { name: /module not initialized/i }),
    ).toBeInTheDocument();
    expect(screen.getAllByText('NOT INITIALIZED').length).toBeGreaterThan(0);
    expect(screen.getByText('Test Module')).toBeInTheDocument();
  });
});
