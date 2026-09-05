import { CartesianGrid, Line, LineChart, ReferenceArea, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

import { RISK_BANDS } from '@/config/risk';
import { EmptyChartState } from '../EmptyChartState';
import { CHART_HEIGHT, axisProps, chartColors, formatTime, tooltipStyle } from './chartTheme';
import type { RiskHistoryPoint } from '@/types';

interface RiskTrendChartProps {
  data: RiskHistoryPoint[] | null;
}

export function RiskTrendChart({ data }: RiskTrendChartProps) {
  if (!data) {
    return (
      <EmptyChartState detail="Historical risk scores appear once the Risk Assessment & Decision Engine produces them." />
    );
  }
  if (data.length === 0) {
    return <EmptyChartState message="NO RISK HISTORY" />;
  }

  const colors = chartColors();
  const bandFill = [colors.success, colors.info, colors.warning, colors.warning, colors.danger];

  return (
    <ResponsiveContainer width="100%" height={CHART_HEIGHT}>
      <LineChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
        {RISK_BANDS.map((band, index) => (
          <ReferenceArea
            key={band.classification}
            y1={band.min}
            y2={band.max}
            fill={bandFill[index]}
            fillOpacity={0.05}
            stroke="none"
          />
        ))}
        <CartesianGrid stroke={colors.grid} strokeDasharray="2 4" vertical={false} />
        <XAxis dataKey="timestamp" tickFormatter={formatTime} stroke={colors.axis} {...axisProps} />
        <YAxis domain={[0, 100]} stroke={colors.axis} {...axisProps} />
        <Tooltip {...tooltipStyle(colors)} labelFormatter={formatTime} />
        <Line
          type="monotone"
          dataKey="score"
          name="Risk score"
          stroke={colors.warning}
          strokeWidth={1.5}
          dot={false}
        />
      </LineChart>
    </ResponsiveContainer>
  );
}
