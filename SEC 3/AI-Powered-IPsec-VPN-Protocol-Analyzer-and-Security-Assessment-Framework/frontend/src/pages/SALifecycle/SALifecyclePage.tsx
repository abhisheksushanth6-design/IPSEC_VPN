import { KeyRound } from 'lucide-react';

import { ModulePlaceholder } from '@/components/ui';

export function SALifecyclePage() {
  return (
    <ModulePlaceholder
      title="SA Lifecycle"
      description="Security Association negotiation, rekey and teardown."
      icon={KeyRound}
      breadcrumbs={[{ label: 'Security Analysis' }, { label: 'SA Lifecycle' }]}
    />
  );
}
