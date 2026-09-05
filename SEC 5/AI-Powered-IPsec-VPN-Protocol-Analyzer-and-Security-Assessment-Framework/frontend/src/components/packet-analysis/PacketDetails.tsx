import { PackageSearch, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

import { EmptyState, LoadingState } from '@/components/states';
import { cn } from '@/utils/cn';
import { IPsecDetails, NetworkDetails, PacketSummary, ParserStatus, RawPacketViewer, SecurityFlagBadges, TransportDetails } from './LayerDetails';
import { ProtocolTree } from './ProtocolTree';
import type { PacketAnalysisController } from '@/hooks';

type Tab = 'layers' | 'tree' | 'raw';

export function PacketDetails({ controller }: { controller: PacketAnalysisController }) {
  const { detail, detailLoading, selectedId, select } = controller;
  const [tab, setTab] = useState<Tab>('layers');
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => { if (detail) closeRef.current?.focus(); }, [detail?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const tabs: Array<[Tab, string]> = [['layers', 'Layers'], ['tree', 'Protocol tree'], ['raw', 'Raw']];

  return (
    <aside role={detail ? 'dialog' : 'region'} aria-label="Packet details" className="flex min-w-0 flex-col rounded border border-border bg-surface xl:sticky xl:top-[calc(var(--header-height)+1.5rem)] xl:max-h-[calc(100vh-var(--header-height)-3rem)]">
      <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
        <h2 className="text-sm font-medium text-primary">Packet details{detail ? ` — #${detail.number}` : ''}</h2>
        {selectedId ? (
          <button ref={closeRef} type="button" onClick={() => select(null)} aria-label="Close packet details" className="rounded p-1 text-muted hover:bg-elevated hover:text-primary">
            <X aria-hidden className="h-4 w-4" />
          </button>
        ) : null}
      </div>

      {!selectedId ? (
        <div className="p-4"><EmptyState icon={PackageSearch} title="No packet selected" description="Select a packet to inspect its network, transport and IPsec layers." /></div>
      ) : detailLoading || !detail ? (
        <div className="px-4"><LoadingState message="Loading packet details…" /></div>
      ) : (
        <>
          <div role="tablist" aria-label="Detail views" className="flex gap-1 border-b border-border px-3 pt-2">
            {tabs.map(([key, label]) => (
              <button key={key} role="tab" aria-selected={tab === key} onClick={() => setTab(key)} className={cn('rounded-t border-b-2 px-3 py-1.5 text-xs transition-colors', tab === key ? 'border-info text-primary' : 'border-transparent text-muted hover:text-secondary')}>
                {label}
              </button>
            ))}
          </div>
          <div role="tabpanel" className="scrollbar-slim flex-1 overflow-y-auto p-4">
            <div className="mb-3 space-y-2">
              <ParserStatus packet={detail} />
              <SecurityFlagBadges flags={detail.flags} />
            </div>
            {tab === 'layers' ? (
              <>
                <PacketSummary packet={detail} />
                <NetworkDetails ip={detail.ip} />
                <TransportDetails transport={detail.transport} />
                <IPsecDetails ipsec={detail.ipsec} />
              </>
            ) : tab === 'tree' ? <ProtocolTree packet={detail} /> : <RawPacketViewer raw={detail.raw} />}
          </div>
        </>
      )}
    </aside>
  );
}
