import React, { useState } from 'react';
import { ArrowLeft, Check, CheckCircle2, Eye, EyeOff, KeyRound, Loader2, Shield, X, AlertCircle } from 'lucide-react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { authService } from '@/services/authService';
import { ApiError } from '@/services/httpClient';

export function ResetPasswordPage() {
  const location = useLocation();
  const navigate = useNavigate();

  const queryParams = new URLSearchParams(location.search);
  const tokenFromUrl = queryParams.get('token') || '';

  const [token, setToken] = useState(tokenFromUrl);
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [generalError, setGeneralError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

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

    if (!token.trim()) {
      errors.token = 'Reset token is required.';
    }

    if (!password) {
      errors.password = 'New password is required.';
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
      await authService.resetPassword({
        token: token.trim(),
        new_password: password,
      });
      setIsSuccess(true);
    } catch (err) {
      if (err instanceof ApiError) {
        setGeneralError(err.message);
      } else {
        setGeneralError('Failed to reset password. The link may have expired.');
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
            Reset Password
          </h1>
          <p className="mt-1 text-sm text-secondary">
            Set a new secure password for your analyst account
          </p>
        </div>

        {/* Card */}
        <div className="rounded-2xl border border-border bg-surface/90 p-7 shadow-2xl backdrop-blur-md sm:p-8">
          {isSuccess ? (
            <div className="space-y-6 text-center">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-success/15 border border-success/30">
                <CheckCircle2 className="h-6 w-6 text-success" />
              </div>
              <div className="space-y-2">
                <h2 className="text-base font-semibold text-primary">Password Updated Successfully</h2>
                <p className="text-xs text-secondary leading-relaxed">
                  Your credentials have been securely updated. Any previous active sessions have been terminated.
                </p>
              </div>

              <button
                type="button"
                onClick={() => navigate('/login')}
                className="w-full rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white shadow-lg shadow-emerald-950/50 hover:bg-emerald-500 active:bg-emerald-700 transition-all"
              >
                Proceed to Sign In
              </button>
            </div>
          ) : (
            <form className="space-y-4" onSubmit={handleSubmit} noValidate>
              {generalError && (
                <div className="flex items-start gap-3 rounded-lg border border-danger/30 bg-danger/10 p-3.5 text-xs text-danger">
                  <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                  <span>{generalError}</span>
                </div>
              )}

              {/* Reset Token (visible only if not present in URL) */}
              {!tokenFromUrl && (
                <div>
                  <label
                    htmlFor="token"
                    className="block text-xs font-medium text-secondary mb-1"
                  >
                    Reset Security Token
                  </label>
                  <input
                    id="token"
                    type="text"
                    value={token}
                    onChange={(e) => {
                      setToken(e.target.value);
                      if (fieldErrors.token) setFieldErrors((p) => ({ ...p, token: '' }));
                    }}
                    placeholder="Paste single-use token here"
                    className="w-full rounded-lg border border-border bg-background/80 px-3.5 py-2 text-sm text-primary placeholder-muted shadow-inner focus:border-info focus:outline-none focus:ring-1 focus:ring-info"
                  />
                  {fieldErrors.token && (
                    <p className="mt-1 text-xs text-danger">{fieldErrors.token}</p>
                  )}
                </div>
              )}

              {/* New Password */}
              <div>
                <label
                  htmlFor="password"
                  className="block text-xs font-medium text-secondary mb-1"
                >
                  New Password
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

              {/* Password Policy Criteria Checklist */}
              <div className="rounded-lg border border-border/70 bg-elevated/40 p-3 text-2xs space-y-1.5">
                <span className="font-semibold text-secondary block mb-1">
                  Password Requirements:
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
                  Confirm New Password
                </label>
                <div className="relative">
                  <input
                    id="confirmPassword"
                    type={showConfirmPassword ? 'text' : 'password'}
                    value={confirmPassword}
                    onChange={(e) => {
                      setConfirmPassword(e.target.value);
                      if (fieldErrors.confirmPassword)
                        setFieldErrors((p) => ({ ...p, confirmPassword: '' }));
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

              {/* Submit Action */}
              <button
                type="submit"
                disabled={isLoading}
                className="w-full flex items-center justify-center gap-2 rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white shadow-lg shadow-emerald-950/50 hover:bg-emerald-500 active:bg-emerald-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-500 pt-2.5"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span>Updating password...</span>
                  </>
                ) : (
                  <>
                    <KeyRound className="h-4 w-4" />
                    <span>Reset Password</span>
                  </>
                )}
              </button>

              <div className="text-center pt-2">
                <Link
                  to="/login"
                  className="inline-flex items-center gap-1.5 text-xs text-secondary hover:text-primary transition-colors"
                >
                  <ArrowLeft className="h-3.5 w-3.5" />
                  <span>Back to Sign In</span>
                </Link>
              </div>
            </form>
          )}
        </div>

        {/* Footer */}
        <p className="text-center text-2xs text-muted">
          AI-Powered IPsec VPN Protocol Analyzer &middot; Enterprise Security Architecture
        </p>
      </div>
    </div>
  );
}
