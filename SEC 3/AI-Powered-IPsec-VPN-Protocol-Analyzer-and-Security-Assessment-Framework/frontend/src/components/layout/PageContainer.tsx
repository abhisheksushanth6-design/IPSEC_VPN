import type { ReactNode } from 'react';

import { cn } from '@/utils/cn';

interface PageContainerProps {
  children: ReactNode;
  className?: string;
}

/** Consistent width and rhythm for page content. */
export function PageContainer({ children, className }: PageContainerProps) {
  return (
    <div className={cn('mx-auto w-full max-w-[90rem] space-y-6', className)}>
      {children}
    </div>
  );
}
