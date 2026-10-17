import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Filter,
  CheckCircle2,
  AlertTriangle,
  FolderGit2
} from 'lucide-react';
import { OverviewStats } from '../types';

interface MetricsBarProps {
  stats: OverviewStats | null;
}

export const MetricsBar: React.FC<MetricsBarProps> = ({ stats }) => {
  if (!stats) return null;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
      {/* 1. Security Posture Score */}
      <div className="glass-panel p-4 rounded-2xl flex items-center justify-between relative overflow-hidden group hover:border-slate-700 transition-all">
        <div className="space-y-1">
          <span className="text-xs font-medium text-slate-400">Security Posture</span>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white tracking-tight">{stats.posture_score}%</span>
            <span className="text-xs font-semibold text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20">
              ASPM
            </span>
          </div>
          <p className="text-[11px] text-slate-400">Aggregated risk & CVSS weighted score</p>
        </div>
        <div className="w-12 h-12 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
          <ShieldCheck className="w-6 h-6" />
        </div>
      </div>

      {/* 2. Developer Noise Reduction */}
      <div className="glass-panel p-4 rounded-2xl flex items-center justify-between relative overflow-hidden group hover:border-slate-700 transition-all">
        <div className="space-y-1">
          <span className="text-xs font-medium text-slate-400">Noise Reduction</span>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-emerald-400 tracking-tight">
              {stats.noise_reduction_pct}%
            </span>
          </div>
          <p className="text-[11px] text-slate-400">Non-reachable & low-risk alerts filtered</p>
        </div>
        <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
          <Filter className="w-6 h-6" />
        </div>
      </div>

      {/* 3. Patch Validation Pass Rate */}
      <div className="glass-panel p-4 rounded-2xl flex items-center justify-between relative overflow-hidden group hover:border-slate-700 transition-all">
        <div className="space-y-1">
          <span className="text-xs font-medium text-slate-400">Fix Validation Pass</span>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-purple-400 tracking-tight">
              {stats.fix_validation_rate}%
            </span>
          </div>
          <p className="text-[11px] text-slate-400">AI diffs verified clean upon re-scan</p>
        </div>
        <div className="w-12 h-12 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
          <CheckCircle2 className="w-6 h-6" />
        </div>
      </div>

      {/* 4. Actionable PR Blockers */}
      <div className="glass-panel p-4 rounded-2xl flex items-center justify-between relative overflow-hidden group hover:border-slate-700 transition-all">
        <div className="space-y-1">
          <span className="text-xs font-medium text-slate-400">Actionable Blockers</span>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-rose-400 tracking-tight">
              {stats.actionable_blockers}
            </span>
            <span className="text-xs text-slate-400">/ {stats.open_findings} total</span>
          </div>
          <p className="text-[11px] text-slate-400">Prioritized items requiring developer review</p>
        </div>
        <div className="w-12 h-12 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400">
          <AlertTriangle className="w-6 h-6" />
        </div>
      </div>

      {/* 5. Repositories & Scans */}
      <div className="glass-panel p-4 rounded-2xl flex items-center justify-between relative overflow-hidden group hover:border-slate-700 transition-all">
        <div className="space-y-1">
          <span className="text-xs font-medium text-slate-400">Repositories Tracked</span>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white tracking-tight">
              {stats.total_repositories}
            </span>
            <span className="text-xs text-slate-400">({stats.total_scans} scans)</span>
          </div>
          <p className="text-[11px] text-slate-400">Monitored repos with push & PR webhooks</p>
        </div>
        <div className="w-12 h-12 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
          <FolderGit2 className="w-6 h-6" />
        </div>
      </div>
    </div>
  );
};
