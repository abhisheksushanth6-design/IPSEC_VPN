import { Network } from 'lucide-react';

import { ModulePlaceholder } from '@/components/ui';

export function PacketAnalysisPage() {
  return (
    <ModulePlaceholder
      title="Packet Analysis"
      description="Decoded packet records and protocol-level inspection."
      icon={Network}
      breadcrumbs={[{ label: 'Monitoring' }, { label: 'Packet Analysis' }]}
    />
  );
}
