import { Cable } from 'lucide-react';

import { ModulePlaceholder } from '@/components/ui';

export function IPSecSessionsPage() {
  return (
    <ModulePlaceholder
      title="IPsec Sessions"
      description="Tunnel sessions observed between negotiating peers."
      icon={Cable}
      breadcrumbs={[{ label: 'Monitoring' }, { label: 'IPsec Sessions' }]}
    />
  );
}
