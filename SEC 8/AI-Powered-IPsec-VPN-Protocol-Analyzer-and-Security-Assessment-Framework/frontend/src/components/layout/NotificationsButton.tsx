import { Bell } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

/**
 * Notification surface. No events exist yet, so the panel states that
 * plainly. It is wired for the real-time channel added in a later section.
 */
export function NotificationsButton() {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;

    const onPointerDown = (event: MouseEvent) => {
      if (!containerRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };

    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  return (
    <div ref={containerRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        aria-haspopup="dialog"
        aria-label="Notifications, none new"
        className="rounded p-2 text-muted transition-colors hover:bg-elevated hover:text-primary"
      >
        <Bell aria-hidden className="h-4 w-4" />
      </button>

      {open ? (
        <div
          role="dialog"
          aria-label="Notifications"
          className="absolute right-0 top-full z-50 mt-2 w-72 rounded border border-border bg-elevated shadow-xl animate-fade-up"
        >
          <div className="border-b border-border px-4 py-3">
            <h2 className="text-sm font-medium text-primary">Notifications</h2>
          </div>
          <div className="px-4 py-6 text-center">
            <p className="text-sm text-muted">No new notifications</p>
            <p className="mt-1 text-xs text-muted">
              Security events appear here once monitoring is implemented.
            </p>
          </div>
        </div>
      ) : null}
    </div>
  );
}
