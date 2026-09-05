import { GitCompare } from 'lucide-react';

import { ModulePlaceholder } from '@/components/ui';

export function SecurityDriftPage() {
  return (
    <ModulePlaceholder
      title="Security Drift"
      description="Deviation of live sessions from established baselines."
      icon={GitCompare}
      breadcrumbs={[{ label: 'Security Analysis' }, { label: 'Security Drift' }]}
    />
  );
}
