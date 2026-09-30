import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

import { EmptyChartState } from '../EmptyChartState';
import { CHART_HEIGHT, axisProps, chartColors, tooltipStyle } from './chartTheme';

export interface TrafficTypeCount {
  type: string;
  count: number;
}

const TRAFFIC_COLORS: Record<string, string> = {
  VOIP: '#10b981',
  WHATSAPP: '#22c55e',
  EMAIL: '#f59e0b',
  VIDEO: '#a855f7',
  VIDEO_STREAMING: '#a855f7',
  WEB: '#06b6d4',
  WEB_BROWSING: '#06b6d4',
  ICMP: '#38bdf8',
  OTHER: '#64748b',
  GENERIC: '#64748b',
};

interface AITrafficDistributionChartProps {
  data: TrafficTypeCount[] | null;
}

export function AITrafficDistributionChart({ data }: AITrafficDistributionChartProps) {
  if (!data) {
    return (
      <EmptyChartState detail="Payload inference breakdown across VoIP, Web, Email, Video, ICMP and WhatsApp appears once AI Traffic Classification processes sessions." />
    );
  }

  const filtered = data.filter((d) => d.count > 0);

  if (filtered.length === 0) {
    return <EmptyChartState message="NO CLASSIFIED SESSIONS" detail="Upload a capture or trigger classification in AI Traffic Classification." />;
  }

  const colors = chartColors();

  return (
    <ResponsiveContainer width="100%" height={CHART_HEIGHT}>
      <BarChart data={filtered} layout="vertical" margin={{ top: 4, right: 16, left: 8, bottom: 0 }}>
        <CartesianGrid stroke={colors.grid} strokeDasharray="2 4" horizontal={false} />
        <XAxis type="number" stroke={colors.axis} {...axisProps} allowDecimals={false} />
        <YAxis
          type="category"
          dataKey="type"
          width={70}
          stroke={colors.axis}
          {...axisProps}
          tickFormatter={(val: string) => val.replace(/_/g, ' ')}
        />
        <Tooltip
          {...tooltipStyle(colors)}
          formatter={(val: any) => [`${val} sessions`, 'Count']}
          labelFormatter={(label: any) => String(label).replace(/_/g, ' ')}
          cursor={{ fill: colors.grid, fillOpacity: 0.3 }}
        />
        <Bar dataKey="count" name="Classified Flows" radius={[0, 2, 2, 0]} barSize={14}>
          {filtered.map((entry) => (
            <Cell
              key={entry.type}
              fill={TRAFFIC_COLORS[entry.type.toUpperCase()] || colors.info}
            />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
