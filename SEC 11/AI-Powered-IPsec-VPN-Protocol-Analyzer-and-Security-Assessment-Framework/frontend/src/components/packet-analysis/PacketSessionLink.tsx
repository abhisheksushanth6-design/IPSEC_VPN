import { ArrowUpRight, Cable } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { sessionService } from '@/services';
import type { PacketSessionLink as LinkData } from '@/types';

/** Shows the session a packet belongs to, if any. Never guesses. */
export function PacketSessionLink({ packetId }: { packetId: string }) {
  const [link, setLink] = useState<LinkData | null | 'error'>(null);

  useEffect(() => {
    const controller = new AbortController();
    setLink(null);
    sessionService.fetchSessionForPacket(packetId, controller.signal)
      .then(setLink)
      .catch(() => { if (!controller.signal.aborted) setLink('error'); });
    return () => controller.abort();
  }, [packetId]);

  return (
    <section className="border-t border-border py-3">
      <h3 className="text-2xs font-medium text-muted">Session</h3>
      {link === null ? <p className="mt-2 text-xs text-muted">Checking session association…</p>
        : link === 'error' ? <p className="mt-2 text-xs text-muted">Session association unavailable.</p>
        : link.session_id ? (
          <Link to={`/ipsec-sessions?session=${encodeURIComponent(link.session_id)}`} className="mt-2 inline-flex items-center gap-2 rounded border border-border px-2.5 py-1.5 text-xs text-primary transition-colors hover:border-info hover:text-info">
            <Cable aria-hidden className="h-3.5 w-3.5" />View session <span className="font-mono">{link.session_id}</span><ArrowUpRight aria-hidden className="h-3 w-3" />
          </Link>
        ) : <p className="mt-2 text-xs text-muted">No session associated. This packet is not part of a discovered IPsec session.</p>}
    </section>
  );
}
