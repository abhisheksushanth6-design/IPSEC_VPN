import { PanelLeftClose, PanelLeftOpen, X } from 'lucide-react';
import { useEffect, useRef } from 'react';

import { NAVIGATION } from '@/config/navigation';
import { cn } from '@/utils/cn';
import { SidebarBrand } from './SidebarBrand';
import { SidebarNavItem } from './SidebarNavItem';

interface SidebarProps {
  collapsed: boolean;
  onToggleCollapsed: () => void;
  /** Drawer visibility on compact viewports. */
  mobileOpen: boolean;
  onCloseMobile: () => void;
  isCompact: boolean;
}

export function Sidebar({
  collapsed,
  onToggleCollapsed,
  mobileOpen,
  onCloseMobile,
  isCompact,
}: SidebarProps) {
  const panelRef = useRef<HTMLDivElement>(null);

  // On compact viewports the drawer traps Escape and moves focus into itself.
  useEffect(() => {
    if (!isCompact || !mobileOpen) return;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onCloseMobile();
    };

    document.addEventListener('keydown', onKeyDown);
    panelRef.current?.focus();
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [isCompact, mobileOpen, onCloseMobile]);

  // The rail never collapses on compact viewports; it becomes a drawer.
  const isCollapsed = collapsed && !isCompact;

  return (
    <>
      {/* Scrim behind the mobile drawer. */}
      {isCompact && mobileOpen ? (
        <div
          role="presentation"
          onClick={onCloseMobile}
          className="fixed inset-0 z-30 bg-background/80 animate-fade-in lg:hidden"
        />
      ) : null}

      <div
        ref={panelRef}
        tabIndex={-1}
        className={cn(
          'flex shrink-0 flex-col border-r border-border bg-surface transition-[width,transform,visibility] duration-250 ease-out',
          isCollapsed ? 'w-sidebar-collapsed' : 'w-sidebar',
          isCompact
            ? cn(
                // Drawer: above the scrim, and hidden from the tab order when shut.
                'fixed inset-y-0 left-0 z-40 w-sidebar',
                mobileOpen ? 'translate-x-0' : '-translate-x-full invisible',
              )
            : // Desktop rail: sits below the sticky header rather than over it.
              'sticky top-header z-10 h-[calc(100vh-var(--header-height))] translate-x-0',
        )}
        aria-hidden={isCompact && !mobileOpen}
      >
        <div className="flex items-center justify-between gap-2 border-b border-border px-2">
          <SidebarBrand collapsed={isCollapsed} />

          {isCompact ? (
            <button
              type="button"
              onClick={onCloseMobile}
              aria-label="Close navigation"
              className="mr-1 rounded p-2 text-muted transition-colors hover:bg-elevated hover:text-primary"
            >
              <X aria-hidden className="h-4 w-4" />
            </button>
          ) : null}
        </div>

        <nav
          aria-label="Main navigation"
          className="scrollbar-slim flex-1 overflow-y-auto px-2 py-4"
        >
          {NAVIGATION.map((group, groupIndex) => (
            <div key={group.title ?? 'primary'} className={cn(groupIndex > 0 && 'mt-6')}>
              {group.title && !isCollapsed ? (
                <h2 className="px-3 pb-2 text-2xs font-medium text-muted">
                  {group.title}
                </h2>
              ) : null}

              {group.title && isCollapsed ? (
                <div aria-hidden className="mx-3 mb-2 border-t border-border" />
              ) : null}

              <ul className="space-y-0.5">
                {group.items.map((item) => (
                  <SidebarNavItem
                    key={item.path}
                    item={item}
                    collapsed={isCollapsed}
                    onNavigate={isCompact ? onCloseMobile : undefined}
                  />
                ))}
              </ul>
            </div>
          ))}
        </nav>

        {!isCompact ? (
          <div className="border-t border-border p-2">
            <button
              type="button"
              onClick={onToggleCollapsed}
              aria-expanded={!isCollapsed}
              aria-label={isCollapsed ? 'Expand navigation' : 'Collapse navigation'}
              className={cn(
                'flex w-full items-center gap-3 rounded px-3 py-2 text-sm text-muted transition-colors hover:bg-elevated hover:text-secondary',
                isCollapsed && 'justify-center px-0',
              )}
            >
              {isCollapsed ? (
                <PanelLeftOpen aria-hidden className="h-4 w-4" />
              ) : (
                <PanelLeftClose aria-hidden className="h-4 w-4" />
              )}
              {!isCollapsed ? <span>Collapse</span> : null}
            </button>
          </div>
        ) : null}
      </div>
    </>
  );
}
