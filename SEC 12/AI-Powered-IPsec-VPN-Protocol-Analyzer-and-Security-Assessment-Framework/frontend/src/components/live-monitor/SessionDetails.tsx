import { Cable } from 'lucide-react';

import { DetailPanel, DetailSection } from './DetailPanel';
import type { VPNSession } from '@/types';

interface SessionDetailsProps {
  session: VPNSession | null;
  onClose: () => void;
}

export function SessionDetails({ session, onClose }: SessionDetailsProps) {
  return (
    <DetailPanel
      title="Session details"
      icon={Cable}
      emptyTitle="No session selected"
      emptyDescription="Select a VPN session to view its negotiation parameters and state."
      onClose={onClose}
      subject={
        session ? (
          <>
            <DetailSection
              title="Session"
              entries={[
                ['Session ID', session.id],
                ['Source', session.source],
                ['Destination', session.destination],
                ['Start time', session.startedAt],
                ['Duration', `${session.durationSeconds}s`],
                ['Current state', session.state],
              ]}
            />
            <DetailSection
              title="Negotiation"
              entries={[
                ['IKE version', session.ikeVersion ?? '—'],
                ['Cipher', session.cipher ?? '—'],
                ['Authentication', session.authentication ?? '—'],
                ['SA count', session.saCount ?? '—'],
              ]}
            />
            <DetailSection title="Assessment" entries={[['Risk', session.risk ?? 'N/A']]} />
          </>
        ) : null
      }
    />
  );
}
