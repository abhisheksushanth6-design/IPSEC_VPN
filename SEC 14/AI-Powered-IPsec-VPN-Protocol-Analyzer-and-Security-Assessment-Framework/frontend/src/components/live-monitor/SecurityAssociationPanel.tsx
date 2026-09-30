import { KeyRound } from 'lucide-react';

import { EntityTable } from './EntityTable';
import type { MonitorSecurityAssociation } from '@/types';

interface SecurityAssociationPanelProps {
  associations: MonitorSecurityAssociation[] | null;
  selectedId: string | null;
  onSelect: (association: MonitorSecurityAssociation) => void;
}

export function SecurityAssociationPanel({ associations, selectedId, onSelect }: SecurityAssociationPanelProps) {
  return (
    <EntityTable<MonitorSecurityAssociation>
      title="Security Associations"
      description="ESP and AH associations tracked by the SA & protocol state engine."
      icon={KeyRound}
      rows={associations}
      selectedId={selectedId}
      onSelect={onSelect}
      emptyTitle="No Security Associations"
      emptyDescription="No Security Associations observed in current capture buffer."
      emptyStatus="READY"
      quietTitle="No Security Associations observed"
      columns={[
        { key: 'id', header: 'SA ID', render: (a) => <span className="font-mono">{a.id}</span> },
        { key: 'spi', header: 'SPI', render: (a) => <span className="font-mono">{a.spi}</span> },
        { key: 'dir', header: 'Direction', render: (a) => a.direction },
        { key: 'alg', header: 'Algorithm', render: (a) => a.encryption ?? a.integrity ?? '—' },
        { key: 'state', header: 'State', render: (a) => a.state },
        { key: 'created', header: 'Created', render: (a) => <span className="font-mono">{a.createdAt}</span> },
        { key: 'expires', header: 'Expires', render: (a) => <span className="font-mono">{a.expiresAt ?? '—'}</span> },
      ]}
    />
  );
}
