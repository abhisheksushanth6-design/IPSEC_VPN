import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

import { EmptyChartState } from '../EmptyChartState';
import { CHART_HEIGHT, axisProps, chartColors, formatTime, tooltipStyle } from './chartTheme';
import type { TrafficPoint } from '@/types';

interface TrafficTimelineChartProps {
  data: TrafficPoint[] | null;
}

export function TrafficTimelineChart({ data }: TrafficTimelineChartProps) {
  if (!data) {
    return (
      <EmptyChartState detail="Packet counts over time appear once the capture and analysis layers are implemented." />
    );
  }
  if (data.length === 0) {
    return <EmptyChartState message="NO TRAFFIC RECORDED" />;
  }

  const colors = chartColors();
  return (
    <ResponsiveContainer width="100%" height={CHART_HEIGHT}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
        <CartesianGrid stroke={colors.grid} strokeDasharray="2 4" vertical={false} />
        <XAxis dataKey="timestamp" tickFormatter={formatTime} stroke={colors.axis} {...axisProps} />
        <YAxis stroke={colors.axis} {...axisProps} allowDecimals={false} />
        <Tooltip {...tooltipStyle(colors)} labelFormatter={formatTime} />
        <Area
          type="monotone"
          dataKey="packets"
          name="Packets"
          stroke={colors.info}
          fill={colors.info}
          fillOpacity={0.12}
          strokeWidth={1.5}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
