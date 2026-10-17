import React from 'react';
import { Network, ArrowRight, ShieldCheck, ShieldAlert, HelpCircle } from 'lucide-react';

interface CallGraphViewerProps {
  status: 'reachable' | 'unreachable' | 'unknown';
  trace?: {
    chain?: string[];
    entrypoint?: string;
    reachability_type?: string;
    reason?: string;
  };
}

export const CallGraphViewer: React.FC<CallGraphViewerProps> = ({ status, trace }) => {
  const chain = trace?.chain || [];

  return (
    <div className="rounded-xl border border-slate-800 bg-[#0d131f] p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Network className="w-4 h-4 text-indigo-400" />
          <span className="text-xs font-semibold text-slate-200">
            Python AST Reachability Call-Graph
          </span>
        </div>
        <div>
          {status === 'reachable' && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <ShieldAlert className="w-3 h-3" />
              Reachable from Route Entrypoint
            </span>
          )}
          {status === 'unreachable' && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-slate-800 text-slate-400 border border-slate-700">
              <ShieldCheck className="w-3 h-3" />
              Statically Unreachable (Suppressed Noise)
            </span>
          )}
          {status === 'unknown' && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-slate-800 text-slate-400">
              <HelpCircle className="w-3 h-3" />
              Static Check Inconclusive
            </span>
          )}
        </div>
      </div>

      {status === 'reachable' && chain.length > 0 && (
        <div className="space-y-2 pt-1">
          <p className="text-[11px] text-slate-400">
            Execution call trace traversed by Python AST from public entrypoint down to vulnerable symbol:
          </p>
          <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
            {chain.map((node, index) => (
              <React.Fragment key={index}>
                <div
                  className={`px-3 py-1.5 rounded-lg border flex items-center gap-2 ${
                    index === 0
                      ? 'bg-indigo-950/40 border-indigo-500/40 text-indigo-300 font-semibold'
                      : index === chain.length - 1
                      ? 'bg-rose-950/40 border-rose-500/40 text-rose-300 font-semibold'
                      : 'bg-slate-900 border-slate-800 text-slate-300'
                  }`}
                >
                  <span className="w-4 h-4 rounded-full bg-slate-800 text-slate-300 flex items-center justify-center text-[9px] font-sans">
                    {index + 1}
                  </span>
                  <span>{node}</span>
                </div>
                {index < chain.length - 1 && (
                  <ArrowRight className="w-3.5 h-3.5 text-slate-600 shrink-0" />
                )}
              </React.Fragment>
            ))}
          </div>
        </div>
      )}

      {status === 'unreachable' && (
        <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-300 space-y-1">
          <p className="font-medium text-slate-200">
            {trace?.reason || 'No caller paths found from application routes or public entrypoints.'}
          </p>
          <p className="text-slate-400 text-[11px]">
            Guardstack's prioritization engine reduced the priority score for this finding to prevent alert fatigue.
          </p>
        </div>
      )}

      {status === 'unknown' && (
        <p className="text-xs text-slate-400 italic">
          {trace?.reason || 'Language parser not configured for this file format or no explicit entrypoints discovered.'}
        </p>
      )}
    </div>
  );
};
