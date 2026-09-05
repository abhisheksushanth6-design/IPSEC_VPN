import { Compass } from 'lucide-react';
import { Link } from 'react-router-dom';

import { PageContainer } from '@/components/layout';
import { EmptyState } from '@/components/states';
import { PageHeader } from '@/components/ui';

export function NotFoundPage() {
  return (
    <PageContainer>
      <PageHeader title="Page not found" breadcrumbs={[{ label: 'Not found' }]} />

      <EmptyState
        icon={Compass}
        title="This page does not exist"
        description="The address you followed is not part of the application."
        action={
          <Link
            to="/overview"
            className="inline-flex items-center rounded border border-border px-3 py-1.5 text-sm text-primary transition-colors hover:border-info hover:text-info"
          >
            Go to Overview
          </Link>
        }
      />
    </PageContainer>
  );
}
