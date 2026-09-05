import { ShieldAlert } from 'lucide-react';

import { ModulePlaceholder } from '@/components/ui';

export function VulnerabilitiesPage() {
  return (
    <ModulePlaceholder
      title="Vulnerabilities"
      description="Weaknesses identified by the security rule engine."
      icon={ShieldAlert}
      breadcrumbs={[{ label: 'Security Analysis' }, { label: 'Vulnerabilities' }]}
    />
  );
}
