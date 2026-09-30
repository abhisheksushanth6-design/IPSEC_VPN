import React, { useState } from 'react';
import { ArrowLeft, KeyRound, Loader2, Mail, Shield, CheckCircle2, AlertCircle } from 'lucide-react';
import { Link } from 'react-router-dom';
import { authService } from '@/services/authService';

export function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [demoUrl, setDemoUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email.trim() || !emailRegex.test(email.trim())) {
      setError('Please enter a valid email address.');
      return;
    }

    setIsLoading(true);
    try {
      const res = await authService.forgotPassword(email.trim());
      setSubmitted(true);
      if (res.demo_reset_url) {
        setDemoUrl(res.demo_reset_url);
      }
    } catch {
      // Still show generic message to avoid enumeration on network failure or error
      setSubmitted(true);
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
            Forgot your password?
          </h1>
          <p className="mt-1 text-sm text-secondary">
            Enter your registered email address to receive a secure reset link.
          </p>
        </div>

        {/* Card */}
        <div className="rounded-2xl border border-border bg-surface/90 p-7 shadow-2xl backdrop-blur-md sm:p-8">
          {submitted ? (
            <div className="space-y-6 text-center">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-success/15 border border-success/30">
                <CheckCircle2 className="h-6 w-6 text-success" />
              </div>
              <div className="space-y-2">
                <h2 className="text-base font-semibold text-primary">Reset Link Dispatched</h2>
                <p className="text-xs text-secondary leading-relaxed">
                  If an account exists for <span className="font-medium text-primary">{email}</span>, a password reset link has been sent. Please check your inbox.
                </p>
              </div>

              {/* Technical Demo Link Helper */}
              {demoUrl && (
                <div className="rounded-lg border border-info/40 bg-info/10 p-3.5 text-left text-xs">
                  <div className="flex items-center gap-1.5 font-semibold text-info mb-1">
                    <KeyRound className="h-4 w-4" />
                    <span>Technical Demo Quick-Link</span>
                  </div>
                  <p className="text-2xs text-muted mb-2">
                    In development/demonstration mode, you can immediately test the password reset flow using this single-use token:
                  </p>
                  <Link
                    to={demoUrl}
                    className="inline-flex items-center gap-1 font-mono text-2xs text-info hover:underline bg-background/60 border border-info/30 px-2 py-1 rounded"
                  >
                    Proceed to Reset Password &rarr;
                  </Link>
                </div>
              )}

              <Link
                to="/login"
                className="inline-flex items-center justify-center gap-2 w-full rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white shadow-lg shadow-emerald-950/50 hover:bg-emerald-500 active:bg-emerald-700 transition-all"
              >
                <ArrowLeft className="h-4 w-4" />
                <span>Return to Sign In</span>
              </Link>
            </div>
          ) : (
            <form className="space-y-5" onSubmit={handleSubmit} noValidate>
              {error && (
                <div className="flex items-start gap-3 rounded-lg border border-danger/30 bg-danger/10 p-3.5 text-xs text-danger">
                  <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                  <span>{error}</span>
                </div>
              )}

              <div>
                <label
                  htmlFor="email"
                  className="block text-xs font-medium text-secondary mb-1.5"
                >
                  Email Address
                </label>
                <div className="relative">
                  <input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => {
                      setEmail(e.target.value);
                      if (error) setError(null);
                    }}
                    disabled={isLoading}
                    placeholder="analyst@organization.gov"
                    className="w-full rounded-lg border border-border bg-background/80 pl-3.5 pr-10 py-2.5 text-sm text-primary placeholder-muted shadow-inner focus:border-info focus:outline-none focus:ring-1 focus:ring-info"
                  />
                  <Mail className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted pointer-events-none" />
                </div>
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="w-full flex items-center justify-center gap-2 rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white shadow-lg shadow-emerald-950/50 hover:bg-emerald-500 active:bg-emerald-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-500"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span>Sending reset link...</span>
                  </>
                ) : (
                  <span>Send Reset Link</span>
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
