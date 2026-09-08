import { Cable } from 'lucide-react';

import { ProtocolBadge } from '@/components/status';
import { EntityTable } from './EntityTable';
import type { VPNSession } from '@/types';

interface VPNSessionPanelProps {
  sessions: VPNSession[] | null;
  selectedId: string | null;
  onSelect: (session: VPNSession) => void;
}

export function VPNSessionPanel({ sessions, selectedId, onSelect }: VPNSessionPanelProps) {
  return (
    <EntityTable<VPNSession>
      title="Active VPN Sessions"
      description="Tunnel sessions tracked by the session engine."
      icon={Cable}
      rows={sessions}
      selectedId={selectedId}
      onSelect={onSelect}
      emptyTitle="No active sessions"
      emptyDescription="No active VPN sessions discovered in current capture buffer."
      emptyStatus="READY"
      quietTitle="No active VPN sessions"
      columns={[
        { key: 'id', header: 'Session ID', render: (s) => <span className="font-mono">{s.id}</span> },
        { key: 'src', header: 'Source', render: (s) => <span className="font-mono">{s.source}</span> },
        { key: 'dst', header: 'Destination', render: (s) => <span className="font-mono">{s.destination}</span> },
        { key: 'state', header: 'State', render: (s) => s.state },
        { key: 'dur', header: 'Duration', align: 'right', render: (s) => `${s.durationSeconds}s` },
        { key: 'proto', header: 'Protocol', render: (s) => <ProtocolBadge protocol={s.protocol} /> },
        { key: 'risk', header: 'Risk', align: 'right', render: (s) => s.risk ?? 'N/A' },
      ]}
    />
  );
}
