import { Calendar, CheckCircle2, Clock, Database, FileText, Layers, Tag } from 'lucide-react';
import { BaselineActiveBadge } from './BaselineStatusBadge';
import type { BaselineProfile } from '@/types';

interface BaselineMetadataProps {
  profile: BaselineProfile;
}

export function BaselineMetadata({ profile }: BaselineMetadataProps) {
  return (
    <div className="rounded-lg border border-border bg-surface p-5 space-y-4 shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-3">
        <div className="flex items-center gap-2">
          <Database className="h-4 w-4 text-cyan-400" />
          <h3 className="text-sm font-bold text-text-primary">Profile Metadata</h3>
        </div>
        <BaselineActiveBadge isActive={profile.is_active} />
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 text-xs">
        <div className="space-y-1">
          <span className="text-2xs uppercase tracking-wider text-muted flex items-center gap-1">
            <Tag className="h-3 w-3" />
            Identifier
          </span>
          <div className="font-mono text-2xs text-text-primary font-semibold break-all">
            {profile.id}
          </div>
        </div>

        <div className="space-y-1">
          <span className="text-2xs uppercase tracking-wider text-muted flex items-center gap-1">
            <Layers className="h-3 w-3" />
            Profile Version
          </span>
          <div className="font-mono text-xs text-text-primary font-bold">
            Iteration v{profile.version}
          </div>
        </div>

        <div className="space-y-1">
          <span className="text-2xs uppercase tracking-wider text-muted flex items-center gap-1">
            <Tag className="h-3 w-3" />
            Feature Schema
          </span>
          <div className="font-mono text-xs text-text-primary font-bold">
            v{profile.feature_version}
          </div>
        </div>

        <div className="space-y-1">
          <span className="text-2xs uppercase tracking-wider text-muted flex items-center gap-1">
            <CheckCircle2 className="h-3 w-3" />
            Evaluation Status
          </span>
          <div>
            <span
              className={`inline-flex rounded px-1.5 py-0.5 text-2xs font-mono font-medium ${
                profile.status === 'READY'
                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                  : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
              }`}
            >
              {profile.status}
            </span>
          </div>
        </div>
      </div>

      {profile.description && (
        <div className="space-y-1 pt-1">
          <span className="text-2xs uppercase tracking-wider text-muted flex items-center gap-1">
            <FileText className="h-3 w-3" />
            Description
          </span>
          <p className="text-xs text-text-secondary bg-base p-2.5 rounded border border-border">
            {profile.description}
          </p>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between text-2xs text-muted pt-2 border-t border-border">
        <span className="inline-flex items-center gap-1">
          <Calendar className="h-3 w-3" />
          Created: {new Date(profile.created_at).toLocaleString()}
        </span>
        <span className="inline-flex items-center gap-1">
          <Clock className="h-3 w-3" />
          Last Updated: {new Date(profile.updated_at).toLocaleString()}
        </span>
      </div>
    </div>
  );
}
