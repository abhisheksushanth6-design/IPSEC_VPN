import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  Activity,
  FileSearch,
  KeyRound,
  BrainCircuit,
  ShieldCheck,
  ShieldAlert,
  ChevronRight,
} from 'lucide-react';
import { cn } from '@/utils/cn';

export interface PipelineStage {
  id: string;
  name: string;
  layer: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}

export const PIPELINE_STAGES: PipelineStage[] = [
  {
    id: 'live-monitor',
    name: 'Live Telemetry',
    layer: 'L01-02',
    path: '/live-monitor',
    icon: Activity,
    description: 'PCAP capture, interface telemetry & packet pulse',
  },
  {
    id: 'packet-analysis',
    name: 'Protocol Decapsulation',
    layer: 'L03-04',
    path: '/packet-analysis',
    icon: FileSearch,
    description: 'IKE, ESP, AH protocol header inspection',
  },
  {
    id: 'ipsec-sessions',
    name: 'Session Fingerprints',
    layer: 'L04-05',
    path: '/ipsec-sessions',
    icon: KeyRound,
    description: 'SPI correlation, flow tracking & SA state',
  },
  {
    id: 'traffic-analysis',
    name: 'AI Classification',
    layer: 'L06-07',
    path: '/traffic-analysis',
    icon: BrainCircuit,
    description: 'Random Forest classifier, flow features & drift',
  },
  {
    id: 'vulnerabilities',
    name: 'Security Rules',
    layer: 'L08',
    path: '/vulnerabilities',
    icon: ShieldCheck,
    description: 'Cryptographic compliance & vulnerability engine',
  },
  {
    id: 'risk-assessment',
    name: 'Risk & Threat Matrix',
    layer: 'L09-10',
    path: '/risk-assessment',
    icon: ShieldAlert,
    description: 'Composite risk scoring & policy decision engine',
  },
];

interface PipelineProgressionRibbonProps {
  className?: string;
  compact?: boolean;
}

/**
 * End-to-end SIH 26160 Cybersecurity Telemetry & Analysis Pipeline Ribbon.
 * Visually binds Live Telemetry -> Protocol Decapsulation -> Session Fingerprinting
 * -> AI Traffic Classification -> Security Rules -> Risk & Threat Matrix.
 */
export function PipelineProgressionRibbon({
  className,
  compact = false,
}: PipelineProgressionRibbonProps) {
  const location = useLocation();

  const getStageIndex = (pathname: string) => {
    if (pathname.includes('/live-monitor')) return 0;
    if (pathname.includes('/packet-analysis')) return 1;
    if (pathname.includes('/ipsec-sessions') || pathname.includes('/sa-lifecycle')) return 2;
    if (
      pathname.includes('/traffic-analysis') ||
      pathname.includes('/feature-engineering') ||
      pathname.includes('/ai-anomalies') ||
      pathname.includes('/drift-detection')
    )
      return 3;
    if (pathname.includes('/vulnerabilities')) return 4;
    if (pathname.includes('/risk-assessment') || pathname.includes('/threat-matrix')) return 5;
    return -1;
  };

  const activeIndex = getStageIndex(location.pathname);

  return (
    <nav
      aria-label="Security Observatory Analysis Pipeline"
      className={cn(
        'w-full rounded-lg border border-border bg-surface p-2.5 shadow-sm transition-all',
        className
      )}
    >
      <div className="mb-2 flex items-center justify-between px-1 text-2xs text-muted">
        <div className="flex items-center gap-1.5 font-mono uppercase tracking-wider text-primary font-semibold">
          <span className="inline-block h-2 w-2 rounded-full bg-info animate-pulse" />
          <span>IPsec Security Observatory Pipeline</span>
          <span className="text-muted font-normal">| SIH 26160</span>
        </div>
        <div className="hidden sm:flex items-center gap-3 font-mono">
          <span>Passive Metadata Telemetry</span>
          <span>•</span>
          <span>Zero Payload Decryption</span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-3 lg:grid-cols-6">
        {PIPELINE_STAGES.map((stage, idx) => {
          const Icon = stage.icon;
          const isActive = activeIndex === idx;
          const isPassed = activeIndex > idx;

          return (
            <Link
              key={stage.id}
              to={stage.path}
              title={`${stage.name} (${stage.layer}): ${stage.description}`}
              className={cn(
                'group relative flex items-center gap-2 rounded-md border p-2 transition-all',
                isActive
                  ? 'border-info/60 bg-info/10 text-primary shadow-sm ring-1 ring-info/30'
                  : isPassed
                  ? 'border-border/80 bg-surface/80 text-secondary hover:border-info/40 hover:bg-elevated/40'
                  : 'border-border/50 bg-background/40 text-muted hover:border-border hover:bg-surface hover:text-secondary'
              )}
            >
              <div
                className={cn(
                  'flex h-7 w-7 shrink-0 items-center justify-center rounded transition-colors',
                  isActive
                    ? 'bg-info text-white shadow-sm'
                    : isPassed
                    ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                    : 'bg-elevated text-muted group-hover:text-primary'
                )}
              >
                <Icon className="h-3.5 w-3.5" />
              </div>

              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1 font-mono text-[10px] text-muted">
                  <span className={cn(isActive && 'text-info font-bold')}>{stage.layer}</span>
                  {idx < PIPELINE_STAGES.length - 1 && (
                    <ChevronRight className="hidden lg:inline h-2.5 w-2.5 text-muted/60" />
                  )}
                </div>
                <div
                  className={cn(
                    'truncate text-xs font-medium',
                    isActive ? 'font-bold text-primary' : 'text-secondary group-hover:text-primary'
                  )}
                >
                  {stage.name}
                </div>
                {!compact && (
                  <p className="truncate text-[10px] text-muted hidden xl:block">
                    {stage.description}
                  </p>
                )}
              </div>
            </Link>
          );
        })}
      </div>
    </nav>
  );
}
