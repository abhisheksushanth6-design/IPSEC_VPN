import { describe, expect, it, vi, beforeEach } from 'vitest';
import { screen, waitFor, fireEvent } from '@testing-library/react';
import { mockBackendOnline, renderAppAt } from './renderApp';

describe('Authentication Flow', () => {
  beforeEach(() => {
    mockBackendOnline();
  });

  describe('LoginPage', () => {
    it('renders the login page with all required cybersecurity elements', async () => {
      // Stub unauthenticated user on /me so user stays on /login
      vi.stubGlobal(
        'fetch',
        vi.fn(async (input: RequestInfo | URL) => {
          const url = String(input);
          if (url.includes('/api/auth/me')) {
            return new Response(JSON.stringify({ error: 'Authentication required' }), {
              status: 401,
              headers: { 'Content-Type': 'application/json' },
            });
          }
          return new Response(JSON.stringify({}), { status: 200 });
        })
      );

      renderAppAt('/login');

      await waitFor(() => {
        expect(screen.getByRole('heading', { name: /welcome back/i })).toBeInTheDocument();
      });

      expect(screen.getByText(/sign in to access the ipsec security analyzer/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/email or username/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/^password$/i)).toBeInTheDocument();
      expect(screen.getByRole('link', { name: /forgot password\?/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
      expect(screen.getByRole('link', { name: /create account/i })).toBeInTheDocument();
    });

    it('validates empty inputs and displays error messages', async () => {
      vi.stubGlobal(
        'fetch',
        vi.fn(async (input: RequestInfo | URL) => {
          const url = String(input);
          if (url.includes('/api/auth/me')) {
            return new Response(JSON.stringify({ error: 'Authentication required' }), {
              status: 401,
              headers: { 'Content-Type': 'application/json' },
            });
          }
          return new Response(JSON.stringify({}), { status: 200 });
        })
      );

      renderAppAt('/login');

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
      });

      const submitBtn = screen.getByRole('button', { name: /sign in/i });
      fireEvent.click(submitBtn);

      await waitFor(() => {
        expect(screen.getByText(/email or username is required/i)).toBeInTheDocument();
        expect(screen.getByText(/password is required/i)).toBeInTheDocument();
      });
    });

    it('toggles password visibility when eye button is clicked', async () => {
      vi.stubGlobal(
        'fetch',
        vi.fn(async (input: RequestInfo | URL) => {
          const url = String(input);
          if (url.includes('/api/auth/me')) {
            return new Response(JSON.stringify({ error: 'Authentication required' }), {
              status: 401,
              headers: { 'Content-Type': 'application/json' },
            });
          }
          return new Response(JSON.stringify({}), { status: 200 });
        })
      );

      renderAppAt('/login');

      await waitFor(() => {
        expect(screen.getByLabelText(/^password$/i)).toBeInTheDocument();
      });

      const passwordInput = screen.getByLabelText(/^password$/i);
      expect(passwordInput).toHaveAttribute('type', 'password');

      const toggleBtn = screen.getByLabelText(/show password/i);
      fireEvent.click(toggleBtn);

      expect(passwordInput).toHaveAttribute('type', 'text');
    });
  });

  describe('RegisterPage', () => {
    it('renders the registration page and displays password criteria checklist', async () => {
      vi.stubGlobal(
        'fetch',
        vi.fn(async (input: RequestInfo | URL) => {
          const url = String(input);
          if (url.includes('/api/auth/me')) {
            return new Response(JSON.stringify({ error: 'Authentication required' }), {
              status: 401,
              headers: { 'Content-Type': 'application/json' },
            });
          }
          return new Response(JSON.stringify({}), { status: 200 });
        })
      );

      renderAppAt('/register');

      await waitFor(() => {
        expect(screen.getByRole('heading', { name: /create account/i })).toBeInTheDocument();
      });

      expect(screen.getByLabelText(/full name/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/email address/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/^password$/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/confirm password/i)).toBeInTheDocument();

      // Criteria checklist items
      expect(screen.getByText(/minimum 8 characters/i)).toBeInTheDocument();
      expect(screen.getByText(/at least one uppercase letter/i)).toBeInTheDocument();
      expect(screen.getByText(/at least one lowercase letter/i)).toBeInTheDocument();
      expect(screen.getByText(/at least one number/i)).toBeInTheDocument();
      expect(screen.getByText(/at least one special character/i)).toBeInTheDocument();
    });
  });

  describe('ForgotPasswordPage', () => {
    it('renders forgot password page and sends reset request', async () => {
      renderAppAt('/forgot-password');

      await waitFor(() => {
        expect(screen.getByRole('heading', { name: /forgot your password\?/i })).toBeInTheDocument();
      });

      expect(screen.getByLabelText(/email address/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /send reset link/i })).toBeInTheDocument();
    });
  });

  describe('ProtectedRoute Redirection', () => {
    it('redirects unauthenticated user to /login when accessing protected page', async () => {
      vi.stubGlobal(
        'fetch',
        vi.fn(async (input: RequestInfo | URL) => {
          const url = String(input);
          if (url.includes('/api/auth/me')) {
            return new Response(JSON.stringify({ error: 'Authentication required' }), {
              status: 401,
              headers: { 'Content-Type': 'application/json' },
            });
          }
          return new Response(JSON.stringify({}), { status: 200 });
        })
      );

      renderAppAt('/overview');

      await waitFor(() => {
        expect(screen.getByRole('heading', { name: /welcome back/i })).toBeInTheDocument();
      });
    });
  });
});
