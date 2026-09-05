import React, { useState } from 'react';
import { Search, BookOpen, CheckCircle2, XCircle, ChevronRight } from 'lucide-react';
import { SeverityBadge, CategoryBadge } from './FindingStatusBadge';
import type { SecurityRule, RuleCategory } from '@/types';

interface RuleExplorerProps {
  rules: SecurityRule[];
  onSelectRule: (rule: SecurityRule) => void;
  onToggleRule: (ruleId: string, enabled: boolean) => Promise<void>;
  loading?: boolean;
}

export function RuleExplorer({
  rules,
  onSelectRule,
  onToggleRule,
  loading = false,
}: RuleExplorerProps) {
  const [search, setSearch] = useState<string>('');
  const [selectedCategory, setSelectedCategory] = useState<RuleCategory | 'ALL'>('ALL');
  const [togglingRuleId, setTogglingRuleId] = useState<string | null>(null);

  const filteredRules = rules.filter((rule) => {
    if (selectedCategory !== 'ALL' && rule.category !== selectedCategory) {
      return false;
    }
    if (search) {
      const q = search.toLowerCase();
      return (
        rule.id.toLowerCase().includes(q) ||
        rule.name.toLowerCase().includes(q) ||
        rule.description.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const handleToggle = async (e: React.MouseEvent, rule: SecurityRule) => {
    e.stopPropagation();
    try {
      setTogglingRuleId(rule.id);
      await onToggleRule(rule.id, !rule.enabled);
    } finally {
      setTogglingRuleId(null);
    }
  };

  return (
    <div className="space-y-4 rounded-lg border border-border bg-surface p-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-border/60 pb-3">
        <div className="flex items-center gap-2">
          <BookOpen className="h-4 w-4 text-blue-400" />
          <h3 className="text-sm font-semibold text-text-primary">
            Rule Catalog ({filteredRules.length}/{rules.length})
          </h3>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Category Filter */}
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value as RuleCategory | 'ALL')}
            className="rounded border border-border bg-surface-subtle px-2.5 py-1 text-xs text-text-primary focus:border-rose-500 focus:outline-none"
          >
            <option value="ALL">All Categories</option>
            <option value="CRYPTO">Cryptography</option>
            <option value="IKE">IKE Protocol</option>
            <option value="AUTH">Authentication</option>
            <option value="PROTOCOL">Protocol Integrity</option>
            <option value="SA_LIFECYCLE">SA Lifecycle</option>
            <option value="CONFIGURATION">Configuration</option>
          </select>

          {/* Search */}
          <div className="relative">
            <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-text-muted" />
            <input
              type="text"
              placeholder="Search rules..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="rounded border border-border bg-surface-subtle py-1 pl-8 pr-3 text-xs text-text-primary placeholder:text-text-muted focus:border-rose-500 focus:outline-none"
            />
          </div>
        </div>
      </div>

      {loading ? (
        <div className="py-8 text-center text-xs text-text-secondary">Loading security rules...</div>
      ) : filteredRules.length === 0 ? (
        <div className="py-8 text-center text-xs text-text-secondary">No rules found matching criteria.</div>
      ) : (
        <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2">
          {filteredRules.map((rule) => (
            <div
              key={rule.id}
              onClick={() => onSelectRule(rule)}
              className="group flex flex-col justify-between rounded-lg border border-border/70 bg-surface-subtle p-3 hover:border-border hover:bg-surface-hover/70 transition cursor-pointer space-y-2"
            >
              <div className="space-y-1.5">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-semibold text-rose-400">
                      {rule.id}
                    </span>
                    <SeverityBadge severity={rule.severity} showIcon={false} />
                  </div>

                  {/* Switch Toggle */}
                  <button
                    onClick={(e) => handleToggle(e, rule)}
                    disabled={togglingRuleId === rule.id}
                    className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-medium transition ${
                      rule.enabled
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20'
                        : 'bg-slate-800 text-slate-400 border border-slate-700 hover:bg-slate-700'
                    }`}
                    title={rule.enabled ? 'Click to disable' : 'Click to enable'}
                  >
                    {rule.enabled ? (
                      <>
                        <CheckCircle2 className="h-3 w-3" /> Enabled
                      </>
                    ) : (
                      <>
                        <XCircle className="h-3 w-3" /> Disabled
                      </>
                    )}
                  </button>
                </div>

                <h4 className="text-xs font-semibold text-text-primary line-clamp-1">{rule.name}</h4>
                <p className="text-[11px] text-text-secondary line-clamp-2 leading-relaxed">
                  {rule.description}
                </p>
              </div>

              <div className="flex items-center justify-between pt-2 border-t border-border/40 text-[11px]">
                <CategoryBadge category={rule.category} className="py-0 px-1 text-[10px]" />
                <span className="flex items-center gap-0.5 text-text-muted group-hover:text-cyan-400 transition font-mono">
                  Inspect <ChevronRight className="h-3 w-3" />
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
