import { Fingerprint } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export function ViewFingerprintLink({ sessionId }: { sessionId: string }) {
  const navigate = useNavigate();

  return (
    <button
      type="button"
      onClick={() => navigate(`/baseline-profiling?session_id=${encodeURIComponent(sessionId)}&tab=fingerprints`)}
      className="inline-flex items-center gap-1.5 rounded border border-border bg-surface px-2.5 py-1 text-2xs font-medium text-text-secondary hover:border-cyan-500 hover:text-cyan-400 transition"
    >
      <Fingerprint className="h-3 w-3 text-cyan-400" />
      <span>View Fingerprint</span>
    </button>
  );
}
