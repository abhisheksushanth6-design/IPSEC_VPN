import { Cable, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { EmptyState, LoadingState } from '@/components/states';
import { cn } from '@/utils/cn';
import { SessionSALinks } from './SessionSALinks';
import { AHInformation, ESPInformation, IKEInformation, SessionActivity, SessionGraph, SessionOverview, SessionPacketList, SessionProtocolSummary, SessionTimeline } from './SessionDetailSections';
import type { SessionController } from '@/hooks';

type Tab = 'overview' | 'timeline' | 'packets' | 'ipsec';

export function SessionDetails({ controller }: { controller: SessionController }) {
  const { detail, detailLoading, selectedId, select } = controller;
  const [tab, setTab] = useState<Tab>('overview');
  const closeRef = useRef<HTMLButtonElement>(null);
  const navigate = useNavigate();

  useEffect(() => { if (detail) closeRef.current?.focus(); }, [detail?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const tabs: Array<[Tab, string]> = [['overview', 'Overview'], ['timeline', 'Timeline'], ['packets', 'Packets'], ['ipsec', 'IPsec / IKE']];

  return (
    <aside role={detail ? 'dialog' : 'region'} aria-label="Session details" className="flex min-w-0 flex-col rounded border border-border bg-surface xl:sticky xl:top-[calc(var(--header-height)+1.5rem)] xl:max-h-[calc(100vh-var(--header-height)-3rem)]">
      <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
        <h2 className="truncate text-sm font-medium text-primary">Session details{detail ? ` — ${detail.id}` : ''}</h2>
        {selectedId ? <button ref={closeRef} type="button" onClick={() => select(null)} aria-label="Close session details" className="rounded p-1 text-muted hover:bg-elevated hover:text-primary"><X aria-hidden className="h-4 w-4" /></button> : null}
      </div>

      {!selectedId ? (
        <div className="p-4"><EmptyState icon={Cable} title="No session selected" description="Select a session to view its overview, timeline, packets and IPsec details." /></div>
      ) : detailLoading || !detail ? (
        <div className="px-4"><LoadingState message="Loading session…" /></div>
      ) : (
        <>
          <div role="tablist" aria-label="Session views" className="flex gap-1 border-b border-border px-3 pt-2">
            {tabs.map(([key, label]) => <button key={key} role="tab" aria-selected={tab === key} onClick={() => setTab(key)} className={cn('rounded-t border-b-2 px-3 py-1.5 text-xs transition-colors', tab === key ? 'border-info text-primary' : 'border-transparent text-muted hover:text-secondary')}>{label}</button>)}
          </div>
          <div role="tabpanel" className="scrollbar-slim flex-1 space-y-3 overflow-y-auto p-4">
            {tab === 'overview' ? <><SessionGraph session={detail} /><SessionOverview session={detail} /><SessionProtocolSummary session={detail} /></> : null}
            {tab === 'timeline' ? <><SessionTimeline session={detail} /><SessionActivity session={detail} /></> : null}
            {tab === 'packets' ? <SessionPacketList session={detail} onSelectPacket={(id) => navigate(`/packet-analysis?packet=${encodeURIComponent(id)}`)} /> : null}
            {tab === 'ipsec' ? <><IKEInformation session={detail} /><ESPInformation session={detail} /><AHInformation session={detail} /><SessionSALinks sessionId={detail.id} /></> : null}
          </div>
        </>
      )}
    </aside>
  );
}
