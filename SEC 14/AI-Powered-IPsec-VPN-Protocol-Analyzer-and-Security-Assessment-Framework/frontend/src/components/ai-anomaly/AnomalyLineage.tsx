import React from 'react';
import { CheckCircle2, Layers } from 'lucide-react';

interface AnomalyLineageProps {
  activeStep?: number;
  sessionId?: string;
  baselineId?: string;
  driftAnalysisId?: string;
  modelId?: string;
}

export const AnomalyLineage: React.FC<AnomalyLineageProps> = ({
  activeStep = 7,
  sessionId,
  baselineId,
  driftAnalysisId,
  modelId,
}) => {
  const steps = [
    {
      step: 1,
      layer: 'Layer 01',
      name: 'Packet Capture',
      desc: 'Raw ESP / IKE packets',
      status: 'complete',
    },
    {
      step: 2,
      layer: 'Layer 02',
      name: 'Session Reassembly',
      desc: sessionId ? `Session: ${sessionId.slice(0, 10)}...` : 'Stateful flows',
      status: sessionId ? 'complete' : 'ready',
    },
    {
      step: 3,
      layer: 'Layer 03',
      name: 'SA & Protocol State',
      desc: 'IKE & Child SA state tracking',
      status: 'complete',
    },
    {
      step: 4,
      layer: 'Layer 05',
      name: 'Feature Vector',
      desc: '27 versioned features (v1.0)',
      status: 'complete',
    },
    {
      step: 5,
      layer: 'Layer 06',
      name: 'Baseline Profile',
      desc: baselineId ? `Profile: ${baselineId.slice(0, 8)}...` : 'Empirical distribution',
      status: baselineId ? 'complete' : 'ready',
    },
    {
      step: 6,
      layer: 'Layer 07',
      name: 'Drift Analysis',
      desc: driftAnalysisId ? `Drift: ${driftAnalysisId.slice(0, 8)}...` : 'Statistical divergence',
      status: driftAnalysisId ? 'complete' : 'ready',
    },
    {
      step: 7,
      layer: 'Layer 08',
      name: 'AI / ML Anomaly Engine',
      desc: modelId ? `Model: ${modelId.slice(0, 8)}...` : 'IsolationForest inference',
      status: 'active',
    },
  ];

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
      <div className="flex items-center space-x-2 mb-3 pb-2 border-b border-slate-800">
        <Layers className="w-4 h-4 text-indigo-400" />
        <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
          Multi-Layer End-to-End Pipeline Lineage
        </h4>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2">
        {steps.map((s) => {
          const isActive = s.step === activeStep;
          const isComplete = s.step < activeStep;

          return (
            <div
              key={s.step}
              className={`p-2.5 rounded-lg border text-left relative transition ${
                isActive
                  ? 'bg-indigo-950/40 border-indigo-500/80 shadow-md ring-1 ring-indigo-500/20'
                  : isComplete
                  ? 'bg-slate-950/70 border-slate-800 text-slate-300'
                  : 'bg-slate-950/30 border-slate-850 text-slate-500'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-mono text-slate-400 font-bold">
                  {s.layer}
                </span>
                {isComplete ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                ) : isActive ? (
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-indigo-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-indigo-500"></span>
                  </span>
                ) : null}
              </div>

              <div className="text-xs font-semibold text-white truncate" title={s.name}>
                {s.name}
              </div>

              <div className="text-[10px] text-slate-400 truncate mt-0.5" title={s.desc}>
                {s.desc}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
