import React, { useState } from 'react';
import { Eye, EyeOff, Loader2, Shield, UserPlus, Check, X, AlertCircle } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '@/context/AuthContext';
import { ApiError } from '@/services/httpClient';

export function RegisterPage() {
  const { user, isAuthenticated, register } = useAuth();
  const navigate = useNavigate();

  React.useEffect(() => {
    if (isAuthenticated && user) {
      navigate('/overview', { replace: true });
    }
  }, [isAuthenticated, user, navigate]);

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [generalError, setGeneralError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  // Dynamic Password Criteria Checklist
  const passwordCriteria = [
    { label: 'Minimum 8 characters', met: password.length >= 8 },
    { label: 'At least one uppercase letter', met: /[A-Z]/.test(password) },
    { label: 'At least one lowercase letter', met: /[a-z]/.test(password) },
    { label: 'At least one number', met: /[0-9]/.test(password) },
    { label: 'At least one special character (!@#$%^&*)', met: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password) },
  ];

  const allCriteriaMet = passwordCriteria.every((c) => c.met);

  const validate = (): boolean => {
    const errors: Record<string, string> = {};

    if (!name.trim() || name.trim().length < 2) {
      errors.name = 'Full name must be at least 2 characters.';
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email.trim()) {
      errors.email = 'Email address is required.';
    } else if (!emailRegex.test(email.trim())) {
      errors.email = 'Please enter a valid email address.';
    }

    const usernameRegex = /^[a-zA-Z0-9_\-\.]{3,64}$/;
    if (!username.trim()) {
      errors.username = 'Username is required.';
    } else if (!usernameRegex.test(username.trim())) {
      errors.username = 'Username must be 3-64 characters (letters, numbers, dots, hyphens, underscores).';
    }

    if (!password) {
      errors.password = 'Password is required.';
    } else if (!allCriteriaMet) {
      errors.password = 'Password does not meet all security requirements.';
    }

    if (!confirmPassword) {
      errors.confirmPassword = 'Confirmation password is required.';
    } else if (password !== confirmPassword) {
      errors.confirmPassword = 'Passwords do not match.';
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
      await register({
        name: name.trim(),
        email: email.trim(),
        username: username.trim(),
        password,
      });
      navigate('/overview', { replace: true });
    } catch (err) {
      if (err instanceof ApiError) {
        setGeneralError(err.message);
      } else {
        setGeneralError('Failed to create account. Please verify your connection.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background px-4 py-12 sm:px-6 lg:px-8">
      {/* Background Cyber Glow Effect */}
      <div className="pointer-events-none fixed inset-0 flex items-center justify-center overflow-hidden">
        <div className="h-[480px] w-[480px] rounded-full bg-emerald-500/5 blur-[120px]" />
      </div>

      <div className="w-full max-w-md space-y-6 relative z-10">
        {/* Branding & Logo */}
        <div className="flex flex-col items-center text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-border bg-surface shadow-xl shadow-black/40">
            <Shield className="h-6 w-6 text-success" />
          </div>
          <h1 className="mt-4 text-2xl font-bold tracking-tight text-primary">
            Create Account
          </h1>
          <p className="mt-1 text-sm text-secondary">
            Register for the IPsec Security Assessment Framework
          </p>
        </div>

        {/* Card */}
        <div className="rounded-2xl border border-border bg-surface/90 p-7 shadow-2xl backdrop-blur-md sm:p-8">
          {generalError && (
            <div className="mb-6 flex items-start gap-3 rounded-lg border border-danger/30 bg-danger/10 p-3.5 text-xs text-danger">
              <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
              <span>{generalError}</span>
            </div>
          )}

          <form className="space-y-4" onSubmit={handleSubmit} noValidate>
            {/* Full Name */}
            <div>
              <label
                htmlFor="name"
                className="block text-xs font-medium text-secondary mb-1"
              >
                Full Name
              </label>
              <input
                id="name"
                type="text"
                value={name}
                onChange={(e) => {
                  setName(e.target.value);
                  if (fieldErrors.name) setFieldErrors((p) => ({ ...p, name: '' }));
                }}
                disabled={isLoading}
                placeholder="Jane Doe"
                className={`w-full rounded-lg border bg-background/80 px-3.5 py-2 text-sm text-primary placeholder-muted shadow-inner focus:border-info focus:outline-none focus:ring-1 focus:ring-info ${
                  fieldErrors.name ? 'border-danger' : 'border-border'
                }`}
              />
              {fieldErrors.name && (
                <p className="mt-1 text-xs text-danger">{fieldErrors.name}</p>
              )}
            </div>

            {/* Email Address */}
            <div>
              <label
                htmlFor="email"
                className="block text-xs font-medium text-secondary mb-1"
              >
                Email Address
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value);
                  if (fieldErrors.email) setFieldErrors((p) => ({ ...p, email: '' }));
                }}
                disabled={isLoading}
                placeholder="jane.doe@organization.org"
                className={`w-full rounded-lg border bg-background/80 px-3.5 py-2 text-sm text-primary placeholder-muted shadow-inner focus:border-info focus:outline-none focus:ring-1 focus:ring-info ${
                  fieldErrors.email ? 'border-danger' : 'border-border'
                }`}
              />
              {fieldErrors.email && (
                <p className="mt-1 text-xs text-danger">{fieldErrors.email}</p>
              )}
            </div>

            {/* Username */}
            <div>
              <label
                htmlFor="username"
                className="block text-xs font-medium text-secondary mb-1"
              >
                Username
              </label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => {
                  setUsername(e.target.value);
                  if (fieldErrors.username) setFieldErrors((p) => ({ ...p, username: '' }));
                }}
                disabled={isLoading}
                placeholder="janedoe"
                className={`w-full rounded-lg border bg-background/80 px-3.5 py-2 text-sm text-primary placeholder-muted shadow-inner focus:border-info focus:outline-none focus:ring-1 focus:ring-info ${
                  fieldErrors.username ? 'border-danger' : 'border-border'
                }`}
              />
              {fieldErrors.username && (
                <p className="mt-1 text-xs text-danger">{fieldErrors.username}</p>
              )}
            </div>

            {/* Password */}
            <div>
              <label
                htmlFor="password"
                className="block text-xs font-medium text-secondary mb-1"
              >
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (fieldErrors.password) setFieldErrors((p) => ({ ...p, password: '' }));
                  }}
                  disabled={isLoading}
                  placeholder="••••••••••••"
                  className={`w-full rounded-lg border bg-background/80 pl-3.5 pr-10 py-2 text-sm text-primary placeholder-muted shadow-inner focus:border-info focus:outline-none focus:ring-1 focus:ring-info ${
                    fieldErrors.password ? 'border-danger' : 'border-border'
                  }`}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((p) => !p)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-primary transition-colors"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {fieldErrors.password && (
                <p className="mt-1 text-xs text-danger">{fieldErrors.password}</p>
              )}
            </div>

            {/* Password Policy Live Requirements Checklist */}
            <div className="rounded-lg border border-border/70 bg-elevated/40 p-3 text-2xs space-y-1.5">
              <span className="font-semibold text-secondary block mb-1">
                Password Security Requirements:
              </span>
              {passwordCriteria.map((c, idx) => (
                <div key={idx} className="flex items-center gap-2">
                  {c.met ? (
                    <Check className="h-3.5 w-3.5 text-success shrink-0" />
                  ) : (
                    <X className="h-3.5 w-3.5 text-muted shrink-0" />
                  )}
                  <span className={c.met ? 'text-success' : 'text-muted'}>
                    {c.label}
                  </span>
                </div>
              ))}
            </div>

            {/* Confirm Password */}
            <div>
              <label
                htmlFor="confirmPassword"
                className="block text-xs font-medium text-secondary mb-1"
              >
                Confirm Password
              </label>
              <div className="relative">
                <input
                  id="confirmPassword"
                  type={showConfirmPassword ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={(e) => {
                    setConfirmPassword(e.target.value);
                    if (fieldErrors.confirmPassword) setFieldErrors((p) => ({ ...p, confirmPassword: '' }));
                  }}
                  disabled={isLoading}
                  placeholder="••••••••••••"
                  className={`w-full rounded-lg border bg-background/80 pl-3.5 pr-10 py-2 text-sm text-primary placeholder-muted shadow-inner focus:border-info focus:outline-none focus:ring-1 focus:ring-info ${
                    fieldErrors.confirmPassword ? 'border-danger' : 'border-border'
                  }`}
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword((p) => !p)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-primary transition-colors"
                  aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
                >
                  {showConfirmPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {fieldErrors.confirmPassword && (
                <p className="mt-1 text-xs text-danger">{fieldErrors.confirmPassword}</p>
              )}
            </div>

            {/* Create Account Action */}
            <button
              type="submit"
              disabled={isLoading}
              className="w-full flex items-center justify-center gap-2 rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white shadow-lg shadow-emerald-950/50 hover:bg-emerald-500 active:bg-emerald-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-500 pt-3"
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>Creating account...</span>
                </>
              ) : (
                <>
                  <UserPlus className="h-4 w-4" />
                  <span>Create Account</span>
                </>
              )}
            </button>
          </form>

          {/* Already have an account */}
          <div className="mt-6 text-center text-xs text-secondary">
            Already have an account?{' '}
            <Link
              to="/login"
              className="font-medium text-info hover:text-info/80 hover:underline transition-colors"
            >
              Sign in
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
