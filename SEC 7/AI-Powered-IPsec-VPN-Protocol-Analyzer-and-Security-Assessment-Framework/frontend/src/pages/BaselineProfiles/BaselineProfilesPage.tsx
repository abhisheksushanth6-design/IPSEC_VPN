import { Fingerprint } from 'lucide-react';

import { ModulePlaceholder } from '@/components/ui';

export function BaselineProfilesPage() {
  return (
    <ModulePlaceholder
      title="Baseline Profiles"
      description="Learned profiles describing normal session behaviour."
      icon={Fingerprint}
      breadcrumbs={[{ label: 'Security Analysis' }, { label: 'Baseline Profiles' }]}
    />
  );
}
