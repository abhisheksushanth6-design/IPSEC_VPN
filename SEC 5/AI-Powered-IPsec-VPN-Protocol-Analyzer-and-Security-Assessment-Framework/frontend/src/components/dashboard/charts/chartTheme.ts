/**
 * Recharts styling that reads the design tokens at render time, so the
 * charts follow the same palette as everything else.
 */

function token(name: string): string {
  if (typeof window === 'undefined') return '#8B97A6';
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value ? `rgb(${value})` : '#8B97A6';
}

export function chartColors() {
  return {
    grid: token('--color-border'),
    axis: token('--color-text-muted'),
    text: token('--color-text-secondary'),
    info: token('--color-info'),
    success: token('--color-success'),
    warning: token('--color-warning'),
    danger: token('--color-danger'),
    surface: token('--color-elevated'),
  };
}

export const CHART_HEIGHT = 200;

export const axisProps = {
  tickLine: false,
  axisLine: false,
  fontSize: 11,
} as const;

export function tooltipStyle(colors: ReturnType<typeof chartColors>) {
  return {
    contentStyle: {
      background: colors.surface,
      border: `1px solid ${colors.grid}`,
      borderRadius: 4,
      fontSize: 12,
      color: colors.text,
    },
    labelStyle: { color: colors.text },
    itemStyle: { color: colors.text },
    cursor: { stroke: colors.grid },
  };
}

/** Compact time label for chart axes. */
export function formatTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}
