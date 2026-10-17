import React from 'react';
import {
  ShieldAlert,
  Key,
  Package,
  Globe,
  CheckCircle2,
  ArrowRight,
  Radio,
  Network
} from 'lucide-react';
import { Finding } from '../types';

interface FindingCardProps {
  finding: Finding;
  onClick: () => void;
}

export const FindingCard: React.FC<FindingCardProps> = ({ finding, onClick }) => {
  const getToolBadge = (tool: string) => {
    switch (tool) {
      case 'semgrep':
        return { label: 'Semgrep SAST', color: 'bg-purple-500/10 text-purple-400 border-purple-500/20', icon: ShieldAlert };
      case 'gitleaks':
        return { label: 'Gitleaks Secrets', color: 'bg-amber-500/10 text-amber-400 border-amber-500/20', icon: Key };
      case 'trivy':
        return { label: 'Trivy SCA', color: 'bg-blue-500/10 text-blue-400 border-blue-500/20', icon: Package };
      case 'zap':
        return { label: 'OWASP ZAP', color: 'bg-rose-500/10 text-rose-400 border-rose-500/20', icon: Globe };
      default:
        return { label: tool, color: 'bg-slate-800 text-slate-300 border-slate-700', icon: ShieldAlert };
    }
  };

  const getPriorityStyle = (score: number) => {
    if (score >= 75) return { text: 'text-rose-400', bg: 'bg-rose-500/10', border: 'border-rose-500/30', label: 'CRITICAL' };
    if (score >= 55) return { text: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/30', label: 'HIGH' };
    if (score >= 35) return { text: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', label: 'MEDIUM' };
    return { text: 'text-slate-400', bg: 'bg-slate-800/60', border: 'border-slate-700', label: 'LOW' };
  };

  const toolInfo = getToolBadge(finding.tool);
  const ToolIcon = toolInfo.icon;
  const priorityStyle = getPriorityStyle(finding.priority_score);

  return (
    <div
      onClick={onClick}
      className="glass-panel p-4 rounded-xl border border-slate-800/80 hover:border-indigo-500/40 hover:bg-[#121a2c]/80 transition-all cursor-pointer group flex flex-col md:flex-row items-start md:items-center justify-between gap-4"
    >
      {/* Left Details */}
      <div className="flex items-start gap-3.5 flex-1 min-w-0">
        {/* Priority Score Gauge */}
        <div className={`w-12 h-12 rounded-xl flex flex-col items-center justify-center shrink-0 border ${priorityStyle.border} ${priorityStyle.bg}`}>
          <span className={`text-sm font-black ${priorityStyle.text}`}>{finding.priority_score}</span>
          <span className="text-[9px] font-bold text-slate-400 uppercase tracking-wider">risk</span>
        </div>

        <div className="space-y-1.5 min-w-0 flex-1">
          {/* Header Badges */}
          <div className="flex flex-wrap items-center gap-2">
            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold border ${toolInfo.color}`}>
              <ToolIcon className="w-3 h-3" />
              {toolInfo.label}
            </span>

            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${priorityStyle.border} ${priorityStyle.text} ${priorityStyle.bg}`}>
              {finding.severity}
            </span>

            {/* Reachability Badge */}
            {finding.reachability_status === 'reachable' && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <Network className="w-3 h-3" />
                Reachable
              </span>
            )}
            {finding.reachability_status === 'unreachable' && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium bg-slate-800 text-slate-400 border border-slate-700">
                Unreachable
              </span>
            )}

            {/* Public Exposure Badge */}
            {finding.exposure_status === 'public_route' && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <Radio className="w-3 h-3" />
                Public Route
              </span>
            )}

            {/* Threat Intel Badges */}
            {finding.cisa_kev && (
              <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-950/80 text-rose-300 border border-rose-600/40">
                CISA KEV ⚠️
              </span>
            )}
            {finding.epss_score !== undefined && finding.epss_score > 0.2 && (
              <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
                EPSS: {(finding.epss_score * 100).toFixed(0)}%
              </span>
            )}

            {/* Fix Validated Badge */}
            {finding.analysis?.fix_validated && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                <CheckCircle2 className="w-3 h-3" />
                Fix Validated
              </span>
            )}
          </div>

          {/* Finding Title */}
          <h3 className="text-sm font-semibold text-slate-100 group-hover:text-indigo-300 transition-colors truncate">
            {finding.title}
          </h3>

          {/* Location & Status */}
          <div className="flex items-center gap-3 text-xs text-slate-400 font-mono">
            <span>{finding.file_path}:{finding.start_line}</span>
            <span>•</span>
            <span className="text-[11px] font-sans text-slate-400 capitalize">status: {finding.status}</span>
          </div>
        </div>
      </div>

      {/* Right Action */}
      <div className="flex items-center gap-2 text-slate-500 group-hover:text-slate-300 transition-colors self-end md:self-center">
        <span className="text-xs font-medium hidden sm:inline">Inspect Fix</span>
        <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
      </div>
    </div>
  );
};