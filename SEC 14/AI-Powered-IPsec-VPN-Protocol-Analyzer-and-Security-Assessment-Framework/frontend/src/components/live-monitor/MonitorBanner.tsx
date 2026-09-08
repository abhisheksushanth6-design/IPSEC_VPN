import { Activity, Radio } from 'lucide-react';
import type { CaptureState } from '@/types';

interface MonitorBannerProps {
  captureState?: CaptureState;
  sourceVM?: string | null;
  nicNumber?: number | null;
}

/** Dynamic status banner reflecting live capture engine readiness and active recording. */
export function MonitorBanner({ captureState, sourceVM, nicNumber }: MonitorBannerProps) {
  const isCapturing = captureState === 'CAPTURING';

  if (isCapturing) {
    return (
      <div
        role="status"
        className="flex items-start gap-3 rounded border border-success/30 bg-success/5 px-4 py-3"
      >
        <Radio aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-success animate-pulse" />
        <div>
          <p className="text-sm font-medium text-success">Live Capture Active</p>
          <p className="mt-0.5 text-xs text-secondary">
            Real IPsec VPN traffic is currently being captured{sourceVM ? ` on ${sourceVM}` : ''}{nicNumber ? ` (NIC ${nicNumber})` : ''} and streamed to the protocol dissection engine.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div
      role="status"
      className="flex items-start gap-3 rounded border border-info/30 bg-info/5 px-4 py-3"
    >
      <Activity aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-info" />
      <div>
        <p className="text-sm font-medium text-primary">Live Capture Engine Ready</p>
        <p className="mt-0.5 text-xs text-secondary">
          Hypervisor NIC tracing and real-time protocol dissection are operational. Select a target interface and start capture to record live IPsec VPN traffic.
        </p>
      </div>
    </div>
  );
}
