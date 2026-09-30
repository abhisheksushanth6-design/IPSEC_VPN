import { useMemo } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Binary } from 'lucide-react';
import { EmptyChartState } from '@/components/dashboard/EmptyChartState';
import {
  axisProps,
  chartColors,
} from '@/components/dashboard/charts/chartTheme';
import type { Packet } from '@/types';
import { cn } from '@/utils/cn';

interface PacketSizeHistogramProps {
  packets: Packet[] | null;
  className?: string;
}

interface SizeBucket {
  range: string;
  count: number;
  min: number;
  max: number;
}

export function PacketSizeHistogram({ packets, className }: PacketSizeHistogramProps) {
  const colors = chartColors();

  const { buckets, avgLength, maxLength, minLength, paddingProfile } = useMemo(() => {
    if (!packets || packets.length === 0) {
      return {
        buckets: [],
        avgLength: 0,
        maxLength: 0,
        minLength: 0,
        paddingProfile: 'No traffic captured',
      };
    }

    const bucketDefs: SizeBucket[] = [
      { range: '0–128B', min: 0, max: 128, count: 0 },
      { range: '129–256B', min: 129, max: 256, count: 0 },
      { range: '257–512B', min: 257, max: 512, count: 0 },
      { range: '513–1024B', min: 513, max: 1024, count: 0 },
      { range: '1025–1420B', min: 1025, max: 1420, count: 0 },
      { range: '>1420B', min: 1421, max: 65535, count: 0 },
    ];

    let sum = 0;
    let max = 0;
    let min = Infinity;

    for (const p of packets) {
      const len = p.length || 0;
      sum += len;
      if (len > max) max = len;
      if (len < min) min = len;

      for (const b of bucketDefs) {
        if (len >= b.min && len <= b.max) {
          b.count++;
          break;
        }
      }
    }

    if (min === Infinity) min = 0;
    const avg = Math.round(sum / packets.length);

    // Analyze padding/clustering
    const b4 = bucketDefs[4]?.count ?? 0;
    const b5 = bucketDefs[5]?.count ?? 0;
    const b0 = bucketDefs[0]?.count ?? 0;
    const mtuCount = b4 + b5;
    const isMtuDominated = mtuCount / packets.length > 0.6;
    const isSmallCluster = b0 / packets.length > 0.6;

    let profile = 'Dispersed multi-modal flow';
    if (isMtuDominated) {
      profile = 'Bulk payload transfer (MTU-bounded ESP clusters)';
    } else if (isSmallCluster) {
      profile = 'Control-plane heavy (IKE negotiations & keepalives)';
    }

    return {
      buckets: bucketDefs,
      avgLength: avg,
      maxLength: max,
      minLength: min,
      paddingProfile: profile,
    };
  }, [packets]);

  if (!packets || packets.length === 0) {
    return (
      <div className="rounded border border-border bg-surface p-4">
        <div className="mb-2 flex items-center justify-between">
          <div>
            <h3 className="text-xs font-semibold text-primary">Packet Size Fingerprint</h3>
            <p className="text-2xs text-muted">Distribution of observable frame lengths</p>
          </div>
          <Binary className="h-4 w-4 text-muted" />
        </div>
        <EmptyChartState detail="Packet length histogram appears once packets are captured and analyzed." />
      </div>
    );
  }

  const customTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const p = payload[0]?.payload as SizeBucket;
      const pct = packets.length > 0 ? ((p.count / packets.length) * 100).toFixed(1) : '0';
      return (
        <div className="rounded border border-border bg-elevated/95 p-2 shadow-lg text-xs font-mono backdrop-blur-sm space-y-1">
          <div className="text-info font-bold">{p.range}</div>
          <div className="text-primary font-bold">{p.count} frames ({pct}%)</div>
          <div className="text-[10px] text-muted">Passive byte length bucket</div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className={cn('rounded border border-border bg-surface p-4 space-y-3', className)}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="flex items-center gap-1.5">
            <Binary className="h-4 w-4 text-info" />
            <h3 className="text-xs font-semibold text-primary">Packet Size Fingerprint</h3>
          </div>
          <p className="text-2xs text-muted">Histogram of observable wire frame lengths</p>
        </div>

        <div className="flex items-center gap-2">
          <span className="rounded bg-info/10 border border-info/30 px-2 py-0.5 text-2xs font-mono font-semibold text-info">
            {paddingProfile}
          </span>
        </div>
      </div>

      {/* Length KPIs */}
      <div className="grid grid-cols-3 gap-2 border-y border-border/60 py-2 font-mono text-2xs">
        <div>
          <span className="text-muted">AVG LENGTH: </span>
          <span className="text-primary font-bold">{avgLength} B</span>
        </div>
        <div>
          <span className="text-muted">MIN LENGTH: </span>
          <span className="text-primary font-bold">{minLength} B</span>
        </div>
        <div>
          <span className="text-muted">MAX LENGTH: </span>
          <span className="text-primary font-bold">{maxLength} B</span>
        </div>
      </div>

      {/* Histogram Canvas */}
      <div className="h-40 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={buckets} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
            <CartesianGrid stroke={colors.grid} strokeDasharray="2 4" vertical={false} />
            <XAxis dataKey="range" stroke={colors.axis} {...axisProps} tick={{ fontSize: 10 }} />
            <YAxis stroke={colors.axis} {...axisProps} allowDecimals={false} />
            <Tooltip content={customTooltip} />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {buckets.map((b, idx) => (
                <Cell
                  key={`hist-${idx}`}
                  fill={
                    b.range.includes('1420') || b.range.includes('>1420')
                      ? '#0EA5E9'
                      : b.range.includes('0–128')
                      ? '#6366F1'
                      : '#3B82F6'
                  }
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
