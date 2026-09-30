import { useState } from 'react';
import {
  Area,
  CartesianGrid,
  ComposedChart,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Zap } from 'lucide-react';
import { EmptyChartState } from '@/components/dashboard/EmptyChartState';
import {
  CHART_HEIGHT,
  axisProps,
  chartColors,
  formatTime,
} from '@/components/dashboard/charts/chartTheme';
import type { TrafficPoint } from '@/types';
import { cn } from '@/utils/cn';

interface IPsecTunnelPulseChartProps {
  data: TrafficPoint[] | null;
  className?: string;
}

/**
 * IPsec Tunnel Pulse — Real-Time Network Telemetry Instrument.
 * Visualizes packet rate and throughput over time from actual capture statistics.
 */
export function IPsecTunnelPulseChart({ data, className }: IPsecTunnelPulseChartProps) {
  const [activeMetric, setActiveMetric] = useState<'both' | 'packets' | 'throughput'>('both');

  if (!data) {
    return (
      <EmptyChartState detail="Packet telemetry over time appears once the capture and analysis layers are engaged." />
    );
  }
  if (data.length === 0) {
    return <EmptyChartState message="NO TRAFFIC RECORDED" />;
  }

  const colors = chartColors();

  // Calculate burst telemetry and peak metrics from actual data
  const totalPackets = data.reduce((acc, p) => acc + (p.packets || 0), 0);
  const peakPackets = Math.max(...data.map((p) => p.packets || 0));
  const avgPackets = totalPackets / (data.length || 1);
  const peakBytes = Math.max(...data.map((p) => p.bytes || 0));
  const latestBurst = data.length > 0 && (data[data.length - 1]?.packets ?? 0) > avgPackets * 1.4;

  const customTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      const pData = payload[0]?.payload as TrafficPoint;
      const bytesVal = pData?.bytes ?? 0;
      return (
        <div className="rounded border border-border bg-elevated/95 p-2.5 shadow-xl text-xs backdrop-blur-sm space-y-1 font-mono">
          <div className="text-2xs text-muted flex items-center justify-between gap-4 border-b border-border pb-1">
            <span>TIMESTAMP: {label}</span>
            <span className="text-info font-bold">L02 TELEMETRY</span>
          </div>
          <div className="flex items-center justify-between gap-4 pt-1">
            <span className="text-secondary flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-info" />
              Packet Rate:
            </span>
            <span className="font-bold text-primary">{pData.packets} pkts/interval</span>
          </div>
          <div className="flex items-center justify-between gap-4">
            <span className="text-secondary flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-emerald-400" />
              Throughput:
            </span>
            <span className="font-bold text-primary">
              {bytesVal >= 1024
                ? `${(bytesVal / 1024).toFixed(1)} KB`
                : `${bytesVal} B`}
            </span>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className={cn('space-y-3', className)}>
      {/* Top telemetry control & peak indicators */}
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 rounded-md border border-border bg-background/60 p-0.5">
            <button
              type="button"
              onClick={() => setActiveMetric('both')}
              className={cn(
                'rounded px-2 py-1 text-2xs font-medium transition-colors',
                activeMetric === 'both'
                  ? 'bg-elevated text-primary shadow-sm font-semibold'
                  : 'text-muted hover:text-secondary'
              )}
            >
              Dual Pulse
            </button>
            <button
              type="button"
              onClick={() => setActiveMetric('packets')}
              className={cn(
                'rounded px-2 py-1 text-2xs font-medium transition-colors',
                activeMetric === 'packets'
                  ? 'bg-elevated text-info shadow-sm font-semibold'
                  : 'text-muted hover:text-secondary'
              )}
            >
              Packets
            </button>
            <button
              type="button"
              onClick={() => setActiveMetric('throughput')}
              className={cn(
                'rounded px-2 py-1 text-2xs font-medium transition-colors',
                activeMetric === 'throughput'
                  ? 'bg-elevated text-emerald-400 shadow-sm font-semibold'
                  : 'text-muted hover:text-secondary'
              )}
            >
              Throughput
            </button>
          </div>

          {latestBurst && (
            <span className="inline-flex items-center gap-1 rounded bg-amber-500/15 border border-amber-500/30 px-2 py-0.5 text-2xs font-bold text-amber-400 animate-pulse">
              <Zap className="h-3 w-3" />
              BURST DETECTED
            </span>
          )}
        </div>

        {/* Telemetry quick callouts */}
        <div className="flex items-center gap-3 font-mono text-2xs text-muted">
          <div>
            <span>PEAK PKTS: </span>
            <span className="text-primary font-bold">{peakPackets}</span>
          </div>
          <span className="text-border">|</span>
          <div>
            <span>PEAK BYTES: </span>
            <span className="text-primary font-bold">
              {peakBytes >= 1024 ? `${(peakBytes / 1024).toFixed(1)} KB` : `${peakBytes} B`}
            </span>
          </div>
        </div>
      </div>

      {/* Main Chart Canvas */}
      <div className="relative rounded-md border border-border/60 bg-background/30 p-2">
        <ResponsiveContainer width="100%" height={CHART_HEIGHT + 30}>
          <ComposedChart data={data} margin={{ top: 12, right: 12, left: -16, bottom: 0 }}>
            <defs>
              <linearGradient id="packetGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={colors.info} stopOpacity={0.35} />
                <stop offset="95%" stopColor={colors.info} stopOpacity={0.0} />
              </linearGradient>
            </defs>

            <CartesianGrid stroke={colors.grid} strokeDasharray="2 4" vertical={false} />
            <XAxis
              dataKey="timestamp"
              tickFormatter={formatTime}
              stroke={colors.axis}
              {...axisProps}
            />
            <YAxis
              yAxisId="left"
              stroke={colors.axis}
              {...axisProps}
              allowDecimals={false}
              label={{
                value: 'pkts',
                position: 'insideTopLeft',
                offset: -4,
                fontSize: 10,
                fill: colors.axis,
              }}
            />
            {activeMetric === 'both' && (
              <YAxis
                yAxisId="right"
                orientation="right"
                stroke={colors.axis}
                {...axisProps}
                tickFormatter={(val) => (val >= 1024 ? `${Math.round(val / 1024)}k` : val)}
              />
            )}

            <Tooltip content={customTooltip} />

            {(activeMetric === 'both' || activeMetric === 'packets') && (
              <Area
                yAxisId="left"
                type="monotone"
                dataKey="packets"
                name="Packets"
                stroke={colors.info}
                fill="url(#packetGradient)"
                strokeWidth={2}
                dot={{ r: 2, fill: colors.info }}
                activeDot={{ r: 5, stroke: colors.info, strokeWidth: 2, fill: colors.surface }}
              />
            )}

            {(activeMetric === 'both' || activeMetric === 'throughput') && (
              <Line
                yAxisId={activeMetric === 'both' ? 'right' : 'left'}
                type="monotone"
                dataKey="bytes"
                name="Bytes"
                stroke="#10B981"
                strokeWidth={1.75}
                dot={false}
                strokeDasharray={activeMetric === 'both' ? '3 3' : undefined}
              />
            )}
          </ComposedChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
