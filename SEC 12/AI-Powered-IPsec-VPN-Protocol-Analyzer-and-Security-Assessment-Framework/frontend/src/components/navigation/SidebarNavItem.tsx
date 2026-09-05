import { NavLink } from 'react-router-dom';

import { cn } from '@/utils/cn';
import type { NavigationItem } from '@/types';

interface SidebarNavItemProps {
  item: NavigationItem;
  collapsed: boolean;
  onNavigate?: () => void;
}

export function SidebarNavItem({ item, collapsed, onNavigate }: SidebarNavItemProps) {
  const Icon = item.icon;

  return (
    <li className="group/item relative">
      <NavLink
        to={item.path}
        onClick={onNavigate}
        aria-label={collapsed ? item.label : undefined}
        className={({ isActive }) =>
          cn(
            'relative flex items-center gap-3 rounded px-3 py-2 text-sm transition-colors duration-150',
            collapsed && 'justify-center px-0',
            isActive
              ? 'bg-elevated text-primary'
              : 'text-muted hover:bg-elevated/60 hover:text-secondary',
          )
        }
      >
        {({ isActive }) => (
          <>
            {/* Active routes carry a marker as well as a colour change. */}
            <span
              aria-hidden
              className={cn(
                'absolute left-0 top-1/2 h-5 w-0.5 -translate-y-1/2 rounded-r bg-info transition-opacity duration-150',
                isActive ? 'opacity-100' : 'opacity-0',
              )}
            />
            <Icon aria-hidden className="h-4 w-4 shrink-0" />
            {!collapsed ? <span className="truncate">{item.label}</span> : null}
          </>
        )}
      </NavLink>

      {/* Tooltip shown only while the rail is collapsed. */}
      {collapsed ? (
        <span
          role="tooltip"
          className="pointer-events-none absolute left-full top-1/2 z-50 ml-2 -translate-y-1/2 whitespace-nowrap rounded border border-border bg-elevated px-2 py-1 text-xs text-primary opacity-0 shadow-lg transition-opacity duration-150 group-hover/item:opacity-100 group-focus-within/item:opacity-100"
        >
          {item.label}
        </span>
      ) : null}
    </li>
  );
}
