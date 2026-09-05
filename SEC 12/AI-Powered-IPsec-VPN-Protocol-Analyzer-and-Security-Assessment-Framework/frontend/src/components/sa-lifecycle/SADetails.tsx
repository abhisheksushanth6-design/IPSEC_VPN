import { KeyRound, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { ViewFeaturesLink } from '@/components/feature-engineering';
import { EmptyState, LoadingState } from '@/components/states';
import { cn } from '@/utils/cn';
import { ChildSAInformation, IKEInformation, SAActivity, SAIdentifiers, SALifecycleGraph, SALifecycleTimeline, SAOverview, SAPacketList, SASessionLink, SAStateCard, SAStateHistory, SecurityParameters } from './SADetailSections';
import type { SAController } from '@/hooks';

type Tab = 'overview' | 'timeline' | 'ike' | 'packets';

export function SADetails({ controller }: { controller: SAController }) {
  const { detail, detailLoading, selectedId, select } = controller;
  const [tab, setTab] = useState<Tab>('overview');
  const closeRef = useRef<HTMLButtonElement>(null);
  const navigate = useNavigate();
  useEffect(() => { if (detail) closeRef.current?.focus(); }, [detail?.id]); // eslint-disable-line react-hooks/exhaustive-deps
  const tabs: Array<[Tab, string]> = [['overview', 'Overview'], ['timeline', 'Timeline'], ['ike', 'IKE / Child SAs'], ['packets', 'Packets']];

  return (
    <aside role={detail ? 'dialog' : 'region'} aria-label="SA details" className="flex min-w-0 flex-col rounded border border-border bg-surface xl:sticky xl:top-[calc(var(--header-height)+1.5rem)] xl:max-h-[calc(100vh-var(--header-height)-3rem)]">
      <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
        <h2 className="truncate text-sm font-medium text-primary">SA details{detail ? ` — ${detail.id}` : ''}</h2>
        {selectedId ? <button ref={closeRef} type="button" onClick={() => select(null)} aria-label="Close SA details" className="rounded p-1 text-muted hover:bg-elevated hover:text-primary"><X aria-hidden className="h-4 w-4" /></button> : null}
      </div>
      {!selectedId ? <div className="p-4"><EmptyState icon={KeyRound} title="No SA selected" description="Select a Security Association to view its state, lifecycle and packets." /></div>
      : detailLoading || !detail ? <div className="px-4"><LoadingState message="Loading SA details…" /></div>
      : (
        <>
          <div role="tablist" aria-label="SA views" className="flex gap-1 border-b border-border px-3 pt-2">{tabs.map(([k, l]) => <button key={k} role="tab" aria-selected={tab === k} onClick={() => setTab(k)} className={cn('rounded-t border-b-2 px-3 py-1.5 text-xs transition-colors', tab === k ? 'border-info text-primary' : 'border-transparent text-muted hover:text-secondary')}>{l}</button>)}</div>
          <div role="tabpanel" className="scrollbar-slim flex-1 space-y-3 overflow-y-auto p-4">
            {tab === 'overview' ? <><SAStateCard sa={detail} /><SALifecycleGraph sa={detail} /><SAOverview sa={detail} /><SAIdentifiers sa={detail} /><SASessionLink sa={detail} /><div className="flex justify-end"><ViewFeaturesLink entityType="SA" entityId={detail.id} /></div></> : null}
            {tab === 'timeline' ? <><SAStateHistory sa={detail} /><SALifecycleTimeline sa={detail} /><SAActivity sa={detail} /></> : null}
            {tab === 'ike' ? <><IKEInformation sa={detail} /><ChildSAInformation sa={detail} onSelect={select} /><SecurityParameters sa={detail} /></> : null}
            {tab === 'packets' ? <SAPacketList sa={detail} onSelectPacket={(id) => navigate(`/packet-analysis?packet=${encodeURIComponent(id)}`)} /> : null}
          </div>
        </>
      )}
    </aside>
  );
}
