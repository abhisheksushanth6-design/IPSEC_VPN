import { FileText } from 'lucide-react';

import { ModulePlaceholder } from '@/components/ui';

export function ReportsPage() {
  return (
    <ModulePlaceholder
      title="Reports"
      description="Generated assessment reports and export history."
      icon={FileText}
      breadcrumbs={[{ label: 'Reporting' }, { label: 'Reports' }]}
    />
  );
}
