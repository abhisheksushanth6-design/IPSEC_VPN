import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

import { EmptyChartState } from '../EmptyChartState';
import { CHART_HEIGHT, axisProps, chartColors, tooltipStyle } from './chartTheme';
import type { SAActivity, SAState } from '@/types';

interface SAActivityChartProps {
  data: SAActivity[] | null;
}

export const SA_STATE_ORDER: SAState[] = [
  'NEGOTIATING',
  'ESTABLISHED',
  'REKEYING',
  'EXPIRED',
  'FAILED',
  'TERMINATED',
];

export function SAActivityChart({ data }: SAActivityChartProps) {
  if (!data) {
    return (
      <EmptyChartState detail="Security Association states appear once the SA Lifecycle Engine is implemented." />
    );
  }
  if (data.length === 0) {
    return <EmptyChartState message="NO SECURITY ASSOCIATIONS" />;
  }

  const colors = chartColors();
  const ordered = SA_STATE_ORDER.map(
    (state) => data.find((d) => d.state === state) ?? { state, count: 0 },
  );

  return (
    <ResponsiveContainer width="100%" height={CHART_HEIGHT}>
      <BarChart data={ordered} layout="vertical" margin={{ top: 4, right: 16, left: 12, bottom: 0 }}>
        <CartesianGrid stroke={colors.grid} strokeDasharray="2 4" horizontal={false} />
        <XAxis type="number" stroke={colors.axis} {...axisProps} allowDecimals={false} />
        <YAxis type="category" dataKey="state" width={84} stroke={colors.axis} {...axisProps} />
        <Tooltip {...tooltipStyle(colors)} cursor={{ fill: colors.grid, fillOpacity: 0.3 }} />
        <Bar dataKey="count" name="Associations" fill={colors.success} radius={[0, 2, 2, 0]} barSize={12} />
      </BarChart>
    </ResponsiveContainer>
  );
}
