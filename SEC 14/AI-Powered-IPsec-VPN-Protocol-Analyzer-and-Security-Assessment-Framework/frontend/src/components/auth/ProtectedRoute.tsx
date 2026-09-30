import { ShieldCheck } from 'lucide-react';
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '@/context/AuthContext';

interface ProtectedRouteProps {
  children?: React.ReactNode;
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-background px-4">
        <div className="flex flex-col items-center gap-4 text-center">
          <div className="relative flex h-14 w-14 items-center justify-center rounded-2xl border border-border bg-surface shadow-2xl">
            <ShieldCheck className="h-7 w-7 text-success animate-pulse" />
            <div className="absolute inset-0 rounded-2xl border border-success/30 animate-ping opacity-25" />
          </div>
          <div>
            <p className="text-sm font-semibold tracking-wide text-primary">IPsec Security Gateway</p>
            <p className="mt-1 text-xs text-muted">Verifying authenticated session credentials...</p>
          </div>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    const redirectTarget = encodeURIComponent(location.pathname + location.search);
    return <Navigate to={`/login?redirect=${redirectTarget}`} replace />;
  }

  return children ? <>{children}</> : <Outlet />;
}
