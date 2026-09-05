import { Activity } from 'lucide-react';

import { ModulePlaceholder } from '@/components/ui';

export function LiveMonitorPage() {
  return (
    <ModulePlaceholder
      title="Live Monitor"
      description="Real-time view of tunnel activity as it is observed."
      icon={Activity}
      breadcrumbs={[{ label: 'Monitoring' }, { label: 'Live Monitor' }]}
    />
  );
}
