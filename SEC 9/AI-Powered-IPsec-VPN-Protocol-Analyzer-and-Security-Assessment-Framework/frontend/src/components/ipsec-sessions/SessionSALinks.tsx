import { ArrowUpRight, KeyRound } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { ProtocolBadge } from '@/components/status';
import { saService } from '@/services';
import type { SAReference } from '@/types';

/** SAs the lifecycle engine linked to this session. Shows nothing invented. */
export function SessionSALinks({ sessionId }: { sessionId: string }) {
  const [refs, setRefs] = useState<SAReference[] | null | 'error'>(null);
  useEffect(() => {
    const c = new AbortController(); setRefs(null);
    saService.fetchForSession(sessionId, c.signal).then((r) => setRefs(r.associations)).catch(() => { if (!c.signal.aborted) setRefs('error'); });
    return () => c.abort();
  }, [sessionId]);
  return (
    <section className="border-t border-border py-3">
      <h3 className="text-2xs font-medium text-muted">Security Associations</h3>
      {refs === null ? <p className="mt-2 text-xs text-muted">Checking SA associations…</p>
        : refs === 'error' ? <p className="mt-2 text-xs text-muted">SA association unavailable.</p>
        : refs.length === 0 ? <p className="mt-2 text-xs text-muted">No SAs linked. Run Discover SAs in SA Lifecycle after discovering sessions.</p>
        : <ul className="mt-2 space-y-1">{refs.map((r) => <li key={r.id}><Link to={`/sa-lifecycle?sa=${encodeURIComponent(r.id)}`} className="flex items-center justify-between gap-2 rounded border border-border px-2 py-1.5 text-xs text-primary hover:border-info"><span className="inline-flex items-center gap-2"><KeyRound aria-hidden className="h-3.5 w-3.5 text-info" /><span className="font-mono">{r.id}</span><ProtocolBadge protocol={r.protocol as 'IKE' | 'ESP' | 'AH'} /></span><span className="inline-flex items-center gap-1 font-mono text-2xs text-muted">{r.state}<ArrowUpRight aria-hidden className="h-3 w-3" /></span></Link></li>)}</ul>}
    </section>
  );
}
