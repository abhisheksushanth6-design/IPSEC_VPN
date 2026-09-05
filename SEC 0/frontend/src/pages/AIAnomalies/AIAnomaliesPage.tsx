import { BrainCircuit } from 'lucide-react';

import { ModulePlaceholder } from '@/components/ui';

export function AIAnomaliesPage() {
  return (
    <ModulePlaceholder
      title="AI Anomalies"
      description="Sessions flagged as anomalous by the detection engine."
      icon={BrainCircuit}
      breadcrumbs={[{ label: 'Security Analysis' }, { label: 'AI Anomalies' }]}
    />
  );
}
