import { ShieldCheck } from 'lucide-react';
import { Outlet } from 'react-router-dom';

/**
 * Application shell. Navigation and dashboard chrome are added in a later
 * section; this provides the frame those views will sit inside.
 */
export function AppLayout() {
  return (
    <div className="flex min-h-full flex-col">
      <header className="border-b border-line">
        <div className="mx-auto flex w-full max-w-5xl items-center gap-3 px-6 py-4">
          <ShieldCheck aria-hidden className="h-5 w-5 text-signal" />
          <span className="text-sm text-muted">
            IPsec VPN Protocol Analyzer and Security Assessment Framework
          </span>
        </div>
      </header>

      <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-12">
        <Outlet />
      </main>

      <footer className="border-t border-line">
        <div className="mx-auto w-full max-w-5xl px-6 py-4 text-xs text-muted">
          Section 0 — project foundation. Security analysis modules are not implemented.
        </div>
      </footer>
    </div>
  );
}
