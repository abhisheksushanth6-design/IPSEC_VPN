import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';
import { chartColors } from '@/components/dashboard/charts/chartTheme';
import { cn } from '@/utils/cn';

interface ProtocolEntry {
  category: 'IKE' | 'ESP' | 'AH' | 'OTHER';
  count: number;
}

interface IPsecProtocolDonutProps {
  data: ProtocolEntry[] | null;
  className?: string;
}

const PROTOCOL_CONFIG: Record<
  'ESP' | 'IKE' | 'AH' | 'OTHER',
  { label: string; full: string; color: string; badge: string }
> = {
  ESP: {
    label: 'ESP',
    full: 'Encapsulating Security Payload (IP Proto 50)',
    color: '#0EA5E9', // Cyan/Sky
    badge: 'border-sky-500/40 bg-sky-500/10 text-sky-400',
  },
  IKE: {
    label: 'IKE',
    full: 'Internet Key Exchange (UDP 500/4500)',
    color: '#6366F1', // Indigo
    badge: 'border-indigo-500/40 bg-indigo-500/10 text-indigo-400',
  },
  AH: {
    label: 'AH',
    full: 'Authentication Header (IP Proto 51)',
    color: '#F59E0B', // Amber
    badge: 'border-amber-500/40 bg-amber-500/10 text-amber-400',
  },
  OTHER: {
    label: 'OTHER',
    full: 'Other / Non-IPsec Transport Telemetry',
    color: '#64748B', // Slate
    badge: 'border-slate-500/40 bg-slate-500/10 text-slate-400',
  },
};

export function IPsecProtocolDonut({ data, className }: IPsecProtocolDonutProps) {
  const colors = chartColors();

  const total = (data ?? []).reduce((acc, curr) => acc + curr.count, 0);

  const chartData = (data ?? []).map((entry) => ({
    name: entry.category,
    value: entry.count,
    color: PROTOCOL_CONFIG[entry.category].color,
    percentage: total > 0 ? ((entry.count / total) * 100).toFixed(1) : '0.0',
  }));

  const customTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const p = payload[0];
      const cfg = PROTOCOL_CONFIG[p.name as keyof typeof PROTOCOL_CONFIG];
      return (
        <div className="rounded border border-border bg-elevated/95 p-2.5 shadow-xl text-xs font-mono space-y-1">
          <div className="flex items-center gap-2 border-b border-border pb-1">
            <span className="h-2 w-2 rounded-full" style={{ backgroundColor: p.payload.color }} />
            <span className="font-bold text-primary">{p.name}</span>
            <span className="text-muted text-[10px]">({p.payload.percentage}%)</span>
          </div>
          <div className="text-secondary text-2xs">{cfg?.full}</div>
          <div className="text-primary font-bold">{p.value.toLocaleString()} packets</div>
        </div>
      );
    }
    return null;
  };

  if (!data || total === 0) {
    return null; // Parent will display the standard empty chart state to satisfy tests
  }

  return (
    <div className={cn('space-y-4', className)}>
      <div className="relative flex items-center justify-center">
        <div className="h-44 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                innerRadius={48}
                outerRadius={68}
                paddingAngle={3}
                dataKey="value"
                stroke={colors.surface}
                strokeWidth={2}
              >
                {chartData.map((entry) => (
                  <Cell key={`cell-${entry.name}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip content={customTooltip} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Center Readout */}
        <div className="pointer-events-none absolute flex flex-col items-center justify-center text-center">
          <span className="font-mono text-xl font-bold text-primary tracking-tight">
            {total.toLocaleString()}
          </span>
          <span className="font-mono text-[9px] uppercase tracking-wider text-muted">
            Total Pkts
          </span>
        </div>
      </div>

      {/* Observability legend with percentages */}
      <div className="grid grid-cols-2 gap-2 text-xs">
        {chartData.map((entry) => {
          return (
            <div
              key={entry.name}
              className="flex items-center justify-between rounded border border-border/70 bg-background/50 px-2.5 py-1.5"
            >
              <div className="flex items-center gap-2 truncate">
                <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: entry.color }} />
                <span className="font-mono text-xs font-semibold text-primary">{entry.name}</span>
              </div>
              <div className="flex items-center gap-1.5 font-mono text-2xs">
                <span className="text-primary font-bold">{entry.value.toLocaleString()}</span>
                <span className="text-muted">({entry.percentage}%)</span>
              </div>
            </div>
          );
        })}
      </div>

      <div className="rounded border border-border/50 bg-elevated/30 p-2 text-[10px] text-muted flex items-center justify-between">
        <span>Header Telemetry:</span>
        <span className="font-mono text-secondary">ESP (Proto 50) • IKE (UDP 500) • AH (Proto 51)</span>
      </div>
    </div>
  );
}
