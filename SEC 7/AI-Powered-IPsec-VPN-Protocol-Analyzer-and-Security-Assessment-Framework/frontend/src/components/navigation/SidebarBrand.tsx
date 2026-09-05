import { ShieldCheck } from 'lucide-react';
import { Link } from 'react-router-dom';

import { BRAND_LINES, PROJECT_NAME } from '@/config/branding';
import { cn } from '@/utils/cn';

/**
 * Sidebar identity mark. The compact wordmark is shorthand only; the official
 * project name is carried in the `title` and in the top header.
 */
export function SidebarBrand({ collapsed }: { collapsed: boolean }) {
  return (
    <Link
      to="/overview"
      title={PROJECT_NAME}
      className={cn(
        'flex items-center gap-3 rounded px-3 py-3 transition-colors hover:bg-elevated/60',
        collapsed && 'justify-center px-0',
      )}
    >
      {/* Mark: a shield over a hairline grid, drawn from Lucide and CSS only. */}
      <span className="relative flex h-8 w-8 shrink-0 items-center justify-center rounded border border-info/40 bg-info/10">
        <ShieldCheck aria-hidden className="h-4 w-4 text-info" />
      </span>

      {!collapsed ? (
        <span className="min-w-0 leading-tight">
          {BRAND_LINES.map((line, index) => (
            <span
              key={line}
              className={cn(
                'block truncate text-xs',
                index === 0 ? 'text-muted' : 'font-medium text-primary',
              )}
            >
              {line}
            </span>
          ))}
        </span>
      ) : (
        <span className="sr-only">{PROJECT_NAME}</span>
      )}
    </Link>
  );
}
