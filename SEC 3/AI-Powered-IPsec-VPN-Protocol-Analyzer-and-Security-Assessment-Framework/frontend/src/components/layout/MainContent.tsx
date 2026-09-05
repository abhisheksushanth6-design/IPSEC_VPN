import type { ReactNode } from 'react';

/** Scrollable region that holds the routed page. */
export function MainContent({ children }: { children: ReactNode }) {
  return (
    <main id="main-content" tabIndex={-1} className="flex-1 px-4 py-6 sm:px-6 lg:px-8">
      {children}
    </main>
  );
}
