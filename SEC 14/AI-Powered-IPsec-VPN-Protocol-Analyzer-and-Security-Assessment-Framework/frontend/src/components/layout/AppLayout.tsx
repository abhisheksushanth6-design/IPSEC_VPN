import { Suspense, useEffect, useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';

import { Sidebar } from '@/components/navigation';
import { PageLoadingState } from '@/components/states';
import { useIsCompactViewport } from '@/hooks';
import { findNavigationItem } from '@/config/navigation';
import { PROJECT_NAME } from '@/config/branding';
import { MainContent } from './MainContent';
import { SystemStatusStrip } from './SystemStatusCluster';
import { TopHeader } from './TopHeader';

/**
 * The application shell: a full-width header above a persistent sidebar and
 * the routed content. Used by every page.
 */
export function AppLayout() {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const isCompact = useIsCompactViewport();
  const location = useLocation();

  // Closing the drawer on navigation stops it covering the page it opened.
  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  // Keep the document title aligned with the current route.
  useEffect(() => {
    const item = findNavigationItem(location.pathname);
    document.title = item ? `${item.label} — ${PROJECT_NAME}` : PROJECT_NAME;
  }, [location.pathname]);

  return (
    <div className="flex min-h-screen flex-col">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded focus:border focus:border-info focus:bg-elevated focus:px-3 focus:py-2 focus:text-sm focus:text-primary"
      >
        Skip to main content
      </a>

      <TopHeader onOpenNavigation={() => setMobileOpen(true)} />
      <SystemStatusStrip />

      <div className="flex flex-1">
        <Sidebar
          collapsed={collapsed}
          onToggleCollapsed={() => setCollapsed((value) => !value)}
          mobileOpen={mobileOpen}
          onCloseMobile={() => setMobileOpen(false)}
          isCompact={isCompact}
        />

        <div className="flex min-w-0 flex-1 flex-col">
          <MainContent>
            <Suspense fallback={<PageLoadingState message="Loading module..." />}>
              <Outlet />
            </Suspense>
          </MainContent>

          <footer className="border-t border-border px-4 py-3 text-2xs text-muted sm:px-6 lg:px-8">
            {PROJECT_NAME} · 14-Layer Security Assessment Framework
          </footer>
        </div>
      </div>
    </div>
  );
}
