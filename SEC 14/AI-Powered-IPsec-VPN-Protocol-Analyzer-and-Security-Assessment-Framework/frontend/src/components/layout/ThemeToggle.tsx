import { Moon, Sun } from 'lucide-react';
import { useTheme } from '@/context/ThemeContext';
import { cn } from '@/utils/cn';

interface ThemeToggleProps {
  className?: string;
  showLabel?: boolean;
}

/**
 * Compact theme toggle button for the navigation bar and settings areas.
 * Matches existing navigation button dimensions exactly (p-2 rounded).
 */
export function ThemeToggle({ className, showLabel = false }: ThemeToggleProps) {
  const { toggleTheme, isDark } = useTheme();

  const title = isDark
    ? 'Dark theme active — Click to switch to Light Mode'
    : 'Light theme active — Click to switch to Dark Mode';

  const ariaLabel = isDark ? 'Switch to light mode' : 'Switch to dark mode';

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label={ariaLabel}
      title={title}
      data-testid="theme-toggle"
      className={cn(
        'group relative rounded p-2 text-muted transition-colors hover:bg-elevated hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-info',
        className,
      )}
    >
      <div className="relative flex h-4 w-4 items-center justify-center">
        {isDark ? (
          <Moon
            aria-hidden="true"
            className="h-4 w-4 text-sky-400 transition-transform duration-300 ease-out group-hover:-rotate-12"
          />
        ) : (
          <Sun
            aria-hidden="true"
            className="h-4 w-4 text-amber-500 transition-transform duration-300 ease-out group-hover:rotate-45"
          />
        )}
      </div>

      {showLabel ? (
        <span className="ml-2 text-xs font-medium text-secondary group-hover:text-primary">
          {isDark ? 'Dark Mode' : 'Light Mode'}
        </span>
      ) : null}

      <span className="sr-only">
        {isDark ? 'Currently Dark Mode' : 'Currently Light Mode'}
      </span>
    </button>
  );
}
