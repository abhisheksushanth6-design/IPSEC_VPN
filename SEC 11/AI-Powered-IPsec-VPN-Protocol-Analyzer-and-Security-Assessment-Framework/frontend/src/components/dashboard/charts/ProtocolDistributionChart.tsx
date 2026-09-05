import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

import { EmptyChartState } from '../EmptyChartState';
import { CHART_HEIGHT, axisProps, chartColors, tooltipStyle } from './chartTheme';
import type { ProtocolDistribution } from '@/types';

interface ProtocolDistributionChartProps {
  data: ProtocolDistribution[] | null;
}

/** Horizontal bars: protocol names read better along the axis than on a pie. */
export function ProtocolDistributionChart({ data }: ProtocolDistributionChartProps) {
  if (!data) {
    return (
      <EmptyChartState detail="Distribution across IKE, ESP, AH, UDP and IP appears once protocol analysis is implemented." />
    );
  }
  if (data.length === 0) {
    return <EmptyChartState message="NO PROTOCOLS OBSERVED" />;
  }

  const colors = chartColors();
  return (
    <ResponsiveContainer width="100%" height={CHART_HEIGHT}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, left: 0, bottom: 0 }}>
        <CartesianGrid stroke={colors.grid} strokeDasharray="2 4" horizontal={false} />
        <XAxis type="number" stroke={colors.axis} {...axisProps} allowDecimals={false} />
        <YAxis type="category" dataKey="protocol" width={44} stroke={colors.axis} {...axisProps} />
        <Tooltip {...tooltipStyle(colors)} cursor={{ fill: colors.grid, fillOpacity: 0.3 }} />
        <Bar dataKey="count" name="Packets" fill={colors.info} radius={[0, 2, 2, 0]} barSize={14} />
      </BarChart>
    </ResponsiveContainer>
  );
}
