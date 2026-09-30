import { useEffect, useRef, useState } from 'react';
import { ChevronDown, LogOut, Moon, ShieldCheck, Sun } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/context/AuthContext';
import { useTheme } from '@/context/ThemeContext';

export function UserMenu() {
  const { user, logout } = useAuth();
  const { isDark, toggleTheme } = useTheme();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  // Close dropdown on click outside or escape key
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    }
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  if (!user) {
    return null;
  }

  const getInitials = (name?: string | null): string => {
    if (!name) return 'US';
    const parts = name.trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) return 'US';
    if (parts.length === 1) {
      const first = parts[0] ?? '';
      return first.slice(0, 2).toUpperCase();
    }
    const firstChar = parts[0]?.[0] ?? '';
    const lastChar = parts[parts.length - 1]?.[0] ?? '';
    return (firstChar + lastChar).toUpperCase();
  };

  const handleLogout = async () => {
    setOpen(false);
    await logout();
    navigate('/login', { replace: true });
  };

  return (
    <div className="relative" ref={menuRef}>
      <button
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        aria-haspopup="true"
        aria-expanded={open}
        aria-label="User profile and account settings"
        className="flex items-center gap-2 rounded-lg border border-border/70 bg-elevated/40 px-2 py-1.5 text-xs text-secondary transition-colors hover:border-border hover:bg-elevated hover:text-primary focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-info"
      >
        {/* Avatar circle with initials */}
        <div className="relative flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-emerald-600/25 border border-emerald-500/40 text-2xs font-bold text-success">
          {getInitials(user.name)}
          <span className="absolute bottom-0 right-0 h-1.5 w-1.5 rounded-full bg-success ring-1 ring-background" />
        </div>

        {/* User Name & Role */}
        <div className="hidden sm:flex flex-col text-left">
          <span className="truncate max-w-[120px] font-medium text-primary text-2xs leading-tight">
            {user.name}
          </span>
          <span className="text-3xs text-muted uppercase tracking-wider font-mono">
            {user.role}
          </span>
        </div>

        <ChevronDown
          className={`h-3.5 w-3.5 text-muted transition-transform duration-200 ${
            open ? 'rotate-180 text-primary' : ''
          }`}
        />
      </button>

      {/* Popover Dropdown Menu */}
      {open && (
        <div
          role="menu"
          aria-orientation="vertical"
          className="absolute right-0 top-full mt-2 w-64 rounded-xl border border-border bg-surface p-2 shadow-2xl z-50 animate-fade-in"
        >
          {/* Header Info */}
          <div className="px-3 py-2.5 border-b border-border/70">
            <p className="font-semibold text-xs text-primary truncate">{user.name}</p>
            <p className="text-2xs text-secondary font-mono truncate">@{user.username}</p>
            <p className="text-2xs text-muted truncate mt-0.5">{user.email}</p>
          </div>

          {/* Session Clearance Badge */}
          <div className="px-3 py-2 my-1 rounded-lg bg-elevated/50 text-2xs space-y-1">
            <div className="flex items-center gap-1.5 text-success font-medium">
              <ShieldCheck className="h-3.5 w-3.5 shrink-0" />
              <span>IPsec Clearance: {user.role.toUpperCase()}</span>
            </div>
            <p className="text-3xs text-muted">
              Live Session Authenticated &middot; Level 14 Assessor
            </p>
          </div>

          {/* Theme / Appearance */}
          <div className="py-1 border-b border-border/70">
            <button
              type="button"
              role="menuitem"
              onClick={toggleTheme}
              className="flex w-full items-center justify-between rounded-lg px-3 py-2 text-xs font-medium text-secondary hover:bg-elevated hover:text-primary transition-colors"
            >
              <div className="flex items-center gap-2">
                {isDark ? (
                  <Moon className="h-3.5 w-3.5 text-sky-400" />
                ) : (
                  <Sun className="h-3.5 w-3.5 text-amber-500" />
                )}
                <span>Theme</span>
              </div>
              <span className="text-2xs font-mono text-muted bg-surface px-1.5 py-0.5 rounded border border-border">
                {isDark ? 'Dark Mode' : 'Light Mode'}
              </span>
            </button>
          </div>

          {/* Actions */}
          <div className="pt-1">
            <button
              type="button"
              role="menuitem"
              onClick={handleLogout}
              className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-xs font-medium text-danger hover:bg-danger/10 hover:text-danger active:bg-danger/20 transition-colors"
            >
              <LogOut className="h-3.5 w-3.5" />
              <span>Sign out</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
