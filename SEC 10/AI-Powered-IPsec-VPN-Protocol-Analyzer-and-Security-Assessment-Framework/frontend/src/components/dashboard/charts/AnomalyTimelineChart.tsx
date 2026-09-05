import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

import { EmptyChartState } from '../EmptyChartState';
import { CHART_HEIGHT, axisProps, chartColors, formatTime, tooltipStyle } from './chartTheme';
import type { AnomalyPoint } from '@/types';

interface AnomalyTimelineChartProps {
  data: AnomalyPoint[] | null;
}

export function AnomalyTimelineChart({ data }: AnomalyTimelineChartProps) {
  if (!data) {
    return (
      <EmptyChartState
        message="MODEL NOT INITIALIZED"
        detail="Anomaly counts over time appear once the AI / ML Anomaly Detection Engine is implemented."
      />
    );
  }
  if (data.length === 0) {
    return <EmptyChartState message="NO ANOMALY HISTORY" />;
  }

  const colors = chartColors();
  return (
    <ResponsiveContainer width="100%" height={CHART_HEIGHT}>
      <BarChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
        <CartesianGrid stroke={colors.grid} strokeDasharray="2 4" vertical={false} />
        <XAxis dataKey="timestamp" tickFormatter={formatTime} stroke={colors.axis} {...axisProps} />
        <YAxis stroke={colors.axis} {...axisProps} allowDecimals={false} />
        <Tooltip {...tooltipStyle(colors)} labelFormatter={formatTime} cursor={{ fill: colors.grid, fillOpacity: 0.3 }} />
        <Bar dataKey="anomalies" name="Anomalies" fill={colors.warning} radius={[2, 2, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
