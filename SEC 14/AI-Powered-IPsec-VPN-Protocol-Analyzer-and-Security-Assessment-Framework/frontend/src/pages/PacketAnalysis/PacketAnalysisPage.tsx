import { AlertTriangle, X } from 'lucide-react';
import { useSearchParams } from 'react-router-dom';

import { PageContainer } from '@/components/layout';
import {
  PacketAnalysisToolbar,
  PacketDetails,
  PacketFilters,
  PacketStatistics,
  PacketTable,
  ProtocolSummary,
  ProtocolAnalysisReportPanel,
  analyzerBadge,
} from '@/components/packet-analysis';
import { PageHeader } from '@/components/ui';
import { usePacketAnalysis } from '@/hooks';

const ERROR_TITLES: Record<string, string> = {
  ANALYSIS_SERVICE_UNAVAILABLE: 'Analysis service unavailable',
  PACKET_PARSE_ERROR: 'Packet parse error',
  CAPTURE_FORMAT_UNSUPPORTED: 'Capture format unsupported',
  UPLOAD_TOO_LARGE: 'Capture too large',
  PACKET_NOT_FOUND: 'Packet not found',
  NO_PACKET_SOURCE: 'Packet source unavailable',
  EMPTY_UPLOAD: 'Empty upload',
};

/**
 * Packet Analysis — Layer 03. Two-pane workspace: packet list on the left,
 * selected packet's decoded layers on the right. All values come from the
 * backend decoder; nothing is synthesised here.
 */
export function PacketAnalysisPage() {
  const [params] = useSearchParams();
  const controller = usePacketAnalysis(params.get('packet'));
  const badge = analyzerBadge(controller.status?.state, controller.status !== null || controller.statusLoading);

  return (
    <PageContainer>
      <PageHeader
        title="Packet Analysis"
        description="Inspect captured network packets and analyze their protocol, header, and IPsec-specific information."
        status={controller.statusLoading ? 'INITIALIZING' : badge.status}
        statusLabel={controller.statusLoading ? 'LOADING' : badge.label}
        breadcrumbs={[{ label: 'Monitoring' }, { label: 'Packet Analysis' }]}
      />

      <PacketAnalysisToolbar controller={controller} />

      {controller.error ? (
        <div role="alert" className="flex items-start justify-between gap-3 rounded border border-danger/30 bg-danger/5 px-4 py-3">
          <div className="flex items-start gap-3">
            <AlertTriangle aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-danger" />
            <div>
              <p className="text-sm font-medium text-primary">{ERROR_TITLES[controller.error.code] ?? 'Request failed'}</p>
              <p className="mt-0.5 text-xs text-secondary">{controller.error.message}</p>
            </div>
          </div>
          <button type="button" onClick={controller.dismissError} aria-label="Dismiss error" className="rounded p-1 text-muted hover:text-primary">
            <X aria-hidden className="h-4 w-4" />
          </button>
        </div>
      ) : null}

      <PacketFilters controller={controller} />

      <div className="grid gap-6 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)] xl:items-start">
        <PacketTable controller={controller} />
        <PacketDetails controller={controller} />
      </div>

      <ProtocolAnalysisReportPanel />

      <div className="grid gap-6 lg:grid-cols-2">
        <ProtocolSummary status={controller.status} />
        <PacketStatistics status={controller.status} />
      </div>
    </PageContainer>
  );
}
