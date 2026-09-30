import { ArrowRight, Cable, Database, Network, Plus } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { BaselineEngineState } from '@/types';

interface EmptyBaselineStateProps {
  state?: BaselineEngineState;
  onOpenBuildModal: () => void;
}

export function EmptyBaselineState({ state, onOpenBuildModal }: EmptyBaselineStateProps) {
  if (state === 'NOT INITIALIZED') {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-center rounded-lg border border-border bg-surface m-6">
        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-surface-muted border border-border text-muted mb-3">
          <Network className="h-6 w-6" />
        </div>
        <h2 className="text-base font-bold text-text-primary">No Packet Observations Loaded</h2>
        <p className="text-xs text-muted max-w-md mt-1 mb-5">
          IPsec session fingerprinting requires network observations from captured traffic.
          Load a pcap capture file to begin extracting protocol features.
        </p>
        <Link to="/packet-analysis">
          <span className="inline-flex items-center gap-2 rounded-md bg-cyan-600 px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-cyan-500 transition">
            <span>Go to Packet Analysis</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </span>
        </Link>
      </div>
    );
  }

  if (state === 'COLLECTING') {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-center rounded-lg border border-border bg-surface m-6">
        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 mb-3">
          <Cable className="h-6 w-6" />
        </div>
        <h2 className="text-base font-bold text-text-primary">Discover IPsec Sessions</h2>
        <p className="text-xs text-muted max-w-md mt-1 mb-5">
          Packets are loaded, but no IPsec VPN sessions have been correlated yet.
          Discover sessions to establish behavioral feature vectors.
        </p>
        <Link to="/ipsec-sessions">
          <span className="inline-flex items-center gap-2 rounded-md bg-cyan-600 px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-cyan-500 transition">
            <span>Go to IPsec Sessions</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </span>
        </Link>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center justify-center p-12 text-center rounded-lg border border-border bg-surface m-6">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 mb-3">
        <Database className="h-6 w-6" />
      </div>
      <h2 className="text-base font-bold text-text-primary">Ready to Construct Baseline</h2>
      <p className="text-xs text-muted max-w-md mt-1 mb-5">
        Observed sessions and protocol features are ready. Build a baseline profile to calculate descriptive
        statistics and establish reference behavior models.
      </p>
      <button
        type="button"
        onClick={onOpenBuildModal}
        className="inline-flex items-center gap-2 rounded-md bg-cyan-600 px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-cyan-500 transition"
      >
        <Plus className="h-3.5 w-3.5" />
        <span>Build Reference Baseline</span>
      </button>
    </div>
  );
}
