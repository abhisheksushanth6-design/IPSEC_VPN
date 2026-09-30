import React, { useState } from 'react';
import { Eye, EyeOff, Loader2, Lock, Shield, AlertCircle, CheckCircle2 } from 'lucide-react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '@/context/AuthContext';
import { ApiError } from '@/services/httpClient';

export function LoginPage() {
  const { user, isAuthenticated, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const queryParams = new URLSearchParams(location.search);
  const redirectPath = queryParams.get('redirect') ? decodeURIComponent(queryParams.get('redirect')!) : '/overview';
  const registeredMsg = queryParams.get('registered');

  React.useEffect(() => {
    if (isAuthenticated && user) {
      navigate(redirectPath, { replace: true });
    }
  }, [isAuthenticated, user, navigate, redirectPath]);

  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [generalError, setGeneralError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<{ identifier?: string; password?: string }>({});

  const validate = (): boolean => {
    const errors: { identifier?: string; password?: string } = {};

    const cleanId = identifier.trim();
    if (!cleanId) {
      errors.identifier = 'Email or username is required.';
    } else if (cleanId.includes('@')) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(cleanId)) {
        errors.identifier = 'Please enter a valid email address.';
      }
    }

    if (!password) {
      errors.password = 'Password is required.';
    }

    setFieldErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setGeneralError(null);

    if (!validate()) {
      return;
    }

    setIsLoading(true);
    try {
      await login({
        identifier: identifier.trim(),
        password,
      });
      navigate(redirectPath, { replace: true });
    } catch (err) {
      if (err instanceof ApiError) {
        setGeneralError(err.message || 'Invalid email/username or password.');
      } else {
        setGeneralError('Unable to connect to security gateway. Please check your network.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleFillDemo = () => {
    setIdentifier('admin@ipsec-analyzer.local');
    setPassword('Analyst@2026!');
    setFieldErrors({});
    setGeneralError(null);
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background px-4 py-12 sm:px-6 lg:px-8">
      {/* Background Cyber Glow Effect */}
      <div className="pointer-events-none fixed inset-0 flex items-center justify-center overflow-hidden">
        <div className="h-[480px] w-[480px] rounded-full bg-emerald-500/5 blur-[120px]" />
      </div>

      <div className="w-full max-w-md space-y-8 relative z-10">
        {/* Branding & Logo */}
        <div className="flex flex-col items-center text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-border bg-surface shadow-xl shadow-black/40">
            <Shield className="h-6 w-6 text-success" />
          </div>
          <h1 className="mt-4 text-2xl font-bold tracking-tight text-primary">
            Welcome Back
          </h1>
          <p className="mt-1 text-sm text-secondary">
            Sign in to access the IPsec Security Analyzer
          </p>
        </div>

        {/* Auth Card */}
        <div className="rounded-2xl border border-border bg-surface/90 p-7 shadow-2xl backdrop-blur-md sm:p-8">
          {registeredMsg && (
            <div className="mb-6 flex items-start gap-3 rounded-lg border border-success/30 bg-success/10 p-3.5 text-xs text-success">
              <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" />
              <span>Registration successful! You may now sign in with your credentials.</span>
            </div>
          )}

          {generalError && (
            <div className="mb-6 flex items-start gap-3 rounded-lg border border-danger/30 bg-danger/10 p-3.5 text-xs text-danger">
              <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
              <span>{generalError}</span>
            </div>
          )}

          <form className="space-y-5" onSubmit={handleSubmit} noValidate>
            {/* Email / Username Field */}
            <div>
              <label
                htmlFor="identifier"
                className="block text-xs font-medium text-secondary mb-1.5"
              >
                Email or Username
              </label>
              <input
                id="identifier"
                name="identifier"
                type="text"
                autoComplete="username"
                value={identifier}
                onChange={(e) => {
                  setIdentifier(e.target.value);
                  if (fieldErrors.identifier) {
                    setFieldErrors((prev) => ({ ...prev, identifier: undefined }));
                  }
                }}
                disabled={isLoading}
                placeholder="name@domain.com or username"
                className={`w-full rounded-lg border bg-background/80 px-3.5 py-2.5 text-sm text-primary placeholder-muted shadow-inner transition-colors focus:border-info focus:outline-none focus:ring-1 focus:ring-info ${
                  fieldErrors.identifier ? 'border-danger' : 'border-border'
                }`}
              />
              {fieldErrors.identifier && (
                <p className="mt-1.5 text-xs text-danger">{fieldErrors.identifier}</p>
              )}
            </div>

            {/* Password Field */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label
                  htmlFor="password"
                  className="block text-xs font-medium text-secondary"
                >
                  Password
                </label>
                <Link
                  to="/forgot-password"
                  className="text-xs text-info hover:text-info/80 hover:underline transition-colors"
                >
                  Forgot password?
                </Link>
              </div>

              <div className="relative">
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (fieldErrors.password) {
                      setFieldErrors((prev) => ({ ...prev, password: undefined }));
                    }
                  }}
                  disabled={isLoading}
                  placeholder="••••••••••••"
                  className={`w-full rounded-lg border bg-background/80 pl-3.5 pr-10 py-2.5 text-sm text-primary placeholder-muted shadow-inner transition-colors focus:border-info focus:outline-none focus:ring-1 focus:ring-info ${
                    fieldErrors.password ? 'border-danger' : 'border-border'
                  }`}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  tabIndex={-1}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-primary transition-colors"
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </button>
              </div>
              {fieldErrors.password && (
                <p className="mt-1.5 text-xs text-danger">{fieldErrors.password}</p>
              )}
            </div>

            {/* Full-width Sign In Action */}
            <button
              type="submit"
              disabled={isLoading}
              className="w-full flex items-center justify-center gap-2 rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white shadow-lg shadow-emerald-950/50 hover:bg-emerald-500 active:bg-emerald-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-500"
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>Verifying credentials...</span>
                </>
              ) : (
                <>
                  <Lock className="h-4 w-4" />
                  <span>Sign in</span>
                </>
              )}
            </button>
          </form>

          {/* Quick Demo Credentials */}
          <div className="mt-6 rounded-lg border border-border/60 bg-elevated/40 p-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-medium text-secondary">Demo Credentials:</span>
              <button
                type="button"
                onClick={handleFillDemo}
                className="text-2xs font-semibold text-success hover:underline transition-colors"
              >
                Auto-fill
              </button>
            </div>
            <div className="mt-1 font-mono text-2xs text-muted flex flex-col gap-0.5">
              <span>admin@ipsec-analyzer.local</span>
              <span>Analyst@2026!</span>
            </div>
          </div>

          {/* Register Link */}
          <div className="mt-6 text-center text-xs text-secondary">
            Don&apos;t have an account?{' '}
            <Link
              to="/register"
              className="font-medium text-info hover:text-info/80 hover:underline transition-colors"
            >
              Create account
            </Link>
          </div>
        </div>

        {/* Footer */}
        <p className="text-center text-2xs text-muted">
          AI-Powered IPsec VPN Protocol Analyzer &middot; Enterprise Security Architecture
        </p>
      </div>
    </div>
  );
}
