import { Menu } from 'lucide-react';

import { PROJECT_NAME } from '@/config/branding';
import { NotificationsButton } from './NotificationsButton';
import { SystemStatusCluster } from './SystemStatusCluster';

interface TopHeaderProps {
  onOpenNavigation: () => void;
}

export function TopHeader({ onOpenNavigation }: TopHeaderProps) {
  return (
    <header className="sticky top-0 z-20 flex h-header items-center gap-3 border-b border-border bg-surface px-3 sm:px-4">
      <button
        type="button"
        onClick={onOpenNavigation}
        aria-label="Open navigation"
        className="rounded p-2 text-muted transition-colors hover:bg-elevated hover:text-primary lg:hidden"
      >
        <Menu aria-hidden className="h-4 w-4" />
      </button>

      {/*
        The official project name in full. It is truncated visually on narrow
        screens but remains complete in the accessibility tree and on hover.
      */}
      <p
        title={PROJECT_NAME}
        className="min-w-0 flex-1 truncate text-sm font-medium text-primary"
      >
        {PROJECT_NAME}
      </p>

      <SystemStatusCluster />

      <div className="ml-auto flex items-center gap-1 xl:ml-2">
        <NotificationsButton />
      </div>
    </header>
  );
}
