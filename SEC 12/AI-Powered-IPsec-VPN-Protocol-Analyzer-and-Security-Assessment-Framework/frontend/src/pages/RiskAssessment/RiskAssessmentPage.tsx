import { Gauge } from 'lucide-react';

import { ModulePlaceholder } from '@/components/ui';

export function RiskAssessmentPage() {
  return (
    <ModulePlaceholder
      title="Risk Assessment"
      description="Prioritised risk derived from all detection sources."
      icon={Gauge}
      breadcrumbs={[{ label: 'Security Analysis' }, { label: 'Risk Assessment' }]}
    />
  );
}
