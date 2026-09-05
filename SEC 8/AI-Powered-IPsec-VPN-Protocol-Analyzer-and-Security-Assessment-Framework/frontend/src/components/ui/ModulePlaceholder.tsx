import type { LucideIcon } from 'lucide-react';

import { EmptyState } from '@/components/states';
import { PageHeader } from './PageHeader';
import { PageContainer } from '@/components/layout';
import type { Breadcrumb } from './PageHeader';

interface ModulePlaceholderProps {
  title: string;
  description: string;
  icon: LucideIcon;
  breadcrumbs?: Breadcrumb[];
}

/**
 * Standard page for a module whose implementation belongs to a later
 * development stage. It states plainly that nothing is running, rather than
 * displaying placeholder security data.
 */
export function ModulePlaceholder({
  title,
  description,
  icon,
  breadcrumbs,
}: ModulePlaceholderProps) {
  return (
    <PageContainer>
      <PageHeader
        title={title}
        description={description}
        status="NOT INITIALIZED"
        breadcrumbs={breadcrumbs}
      />

      <EmptyState
        icon={icon}
        title="Module not initialized"
        description="This module will be implemented in a future development stage. No analysis is running and no data has been collected."
        status="NOT INITIALIZED"
      />
    </PageContainer>
  );
}
