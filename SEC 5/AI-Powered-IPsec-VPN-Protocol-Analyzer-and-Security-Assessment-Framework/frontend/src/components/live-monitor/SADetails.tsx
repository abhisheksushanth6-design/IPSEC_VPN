import { KeyRound } from 'lucide-react';

import { DetailPanel, DetailSection } from './DetailPanel';
import type { SecurityAssociation } from '@/types';

interface SADetailsProps {
  association: SecurityAssociation | null;
  onClose: () => void;
}

/**
 * Key material never appears here. Only algorithm names, identifiers and
 * lifetimes are shown, even once real data exists.
 */
export function SADetails({ association, onClose }: SADetailsProps) {
  return (
    <DetailPanel
      title="Security Association details"
      icon={KeyRound}
      emptyTitle="No Security Association selected"
      emptyDescription="Select an SA to view its algorithms, direction and lifetime."
      onClose={onClose}
      subject={
        association ? (
          <>
            <DetailSection
              title="Identity"
              entries={[
                ['SPI', association.spi],
                ['Direction', association.direction],
                ['Protocol', association.protocol],
                ['State', association.state],
              ]}
            />
            <DetailSection
              title="Algorithms"
              entries={[
                ['Encryption', association.encryption ?? '—'],
                ['Integrity', association.integrity ?? '—'],
                ['Authentication', association.authentication ?? '—'],
              ]}
            />
            <DetailSection
              title="Lifetime"
              entries={[
                ['Created', association.createdAt],
                ['Expires', association.expiresAt ?? '—'],
                ['Lifetime', association.lifetimeSeconds ? `${association.lifetimeSeconds}s` : '—'],
              ]}
            />
          </>
        ) : null
      }
    />
  );
}
