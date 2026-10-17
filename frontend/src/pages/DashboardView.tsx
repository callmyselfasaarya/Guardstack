import React from 'react';
import {
  ShieldAlert,
  CheckCircle2,
  ArrowRight,
  GitPullRequest,
  BarChart3,
  Flame,
  Cpu
} from 'lucide-react';
import { OverviewStats, Finding } from '../types';
import { MetricsBar } from '../components/MetricsBar';

interface DashboardViewProps {
  stats: OverviewStats | null;
  onNavigateTab: (tab: string) => void;
  onOpenScanModal: () => void;
  onSelectFinding: (findingId: string) => void;
  topFindings: Finding[];
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  stats,
  onNavigateTab,
  onOpenScanModal,
  onSelectFinding,
  topFindings,
}) => {
  if (!stats) return null;

  return (
    <div className="space-y-8 animate-in fade-in duration-150">
      {/* Hero ASPM Banner */}
      <div className="relative overflow-hidden rounded-3xl border border-indigo-500/20 bg-gradient-to-r from-slate-950 via-[#0e1628] to-slate-950 p-8 shadow-2xl">
        <div className="absolute -top-24 -right-24 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
          <div className="space-y-2 max-w-2xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/30">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              Guardstack ASPM Security Platform
            </div>
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Prioritize real risks. Eliminate developer fatigue.
            </h2>
            <p className="text-sm text-slate-300 leading-relaxed">
              Guardstack normalizes findings across Semgrep SAST, Gitleaks secrets, and Trivy dependencies, scores real-world risk by combining CVSS, EPSS, and CISA KEV feeds, and auto-validates AI patches in an isolated re-scan loop before posting to PRs.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={() => onNavigateTab('benchmark')}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-all shadow-md"
            >
              <BarChart3 className="w-4 h-4 text-purple-400" />
              <span>Defense Benchmark</span>
            </button>
            <button
              onClick={onOpenScanModal}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-400 hover:to-purple-500 text-white text-xs font-bold transition-all shadow-lg shadow-indigo-500/25"
            >
              <GitPullRequest className="w-4 h-4" />
              <span>Simulate PR Webhook</span>
            </button>
          </div>
        </div>
      </div>

      {/* Metrics Bar */}
      <MetricsBar stats={stats} />

      {/* Core Insights Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <span>Severity Breakdown</span>
            </h3>
            <span className="text-xs text-slate-400">{stats.open_findings} Total Open</span>
          </div>

          <div className="space-y-3 pt-2">
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="font-semibold text-rose-400">Critical</span>
                <span className="text-slate-300 font-mono">{stats.critical_count}</span>
              </div>
              <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-rose-500 rounded-full"
                  style={{ width: `${stats.open_findings ? (stats.critical_count / stats.open_findings) * 100 : 0}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="font-semibold text-amber-400">High</span>
                <span className="text-slate-300 font-mono">{stats.high_count}</span>
              </div>
              <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-amber-500 rounded-full"
                  style={{ width: `${stats.open_findings ? (stats.high_count / stats.open_findings) * 100 : 0}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="font-semibold text-yellow-400">Medium</span>
                <span className="text-slate-300 font-mono">{stats.medium_count}</span>
              </div>
              <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-yellow-500 rounded-full"
                  style={{ width: `${stats.open_findings ? (stats.medium_count / stats.open_findings) * 100 : 0}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="font-semibold text-slate-400">Low / Info</span>
                <span className="text-slate-300 font-mono">{stats.low_count}</span>
              </div>
              <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-slate-600 rounded-full"
                  style={{ width: `${stats.open_findings ? (stats.low_count / stats.open_findings) * 100 : 0}%` }}
                />
              </div>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-[11px] text-slate-400">
            💡 Guardstack prioritizes findings using CVSS, EPSS, and CISA KEV, dropping non-actionable noise by <strong className="text-emerald-400">{stats.noise_reduction_pct}%</strong>.
          </div>
        </div>

        {/* 3-Feed Threat Engine Overview */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Cpu className="w-4 h-4 text-indigo-400" />
            <span>Authoritative 3-Feed Engine</span>
          </h3>

          <div className="space-y-3 text-xs text-slate-300">
            <div className="flex items-start gap-2.5 p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
              <span className="w-5 h-5 rounded-md bg-indigo-500/20 text-indigo-400 flex items-center justify-center font-bold text-[10px] shrink-0">1</span>
              <div>
                <strong className="text-white">CVSS v3 Severity (45%):</strong> Base technical vulnerability severity score (up to 45 pts)
              </div>
            </div>

            <div className="flex items-start gap-2.5 p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
              <span className="w-5 h-5 rounded-md bg-emerald-500/20 text-emerald-400 flex items-center justify-center font-bold text-[10px] shrink-0">2</span>
              <div>
                <strong className="text-white">EPSS Exploit Likelihood (35%):</strong> Empirical 30-day wild exploit probability from FIRST.org (up to 35 pts)
              </div>
            </div>

            <div className="flex items-start gap-2.5 p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
              <span className="w-5 h-5 rounded-md bg-rose-500/20 text-rose-400 flex items-center justify-center font-bold text-[10px] shrink-0">3</span>
              <div>
                <strong className="text-white">CISA KEV Catalog (20%):</strong> Known Exploited Vulnerabilities active in the wild (+20 bonus pts)
              </div>
            </div>
          </div>
        </div>

        {/* Fix Validation Loop Defense */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>Fix Validation Guarantee</span>
            </h3>
            <span className="text-xs font-bold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
              {stats.fix_validation_rate}% Pass Rate
            </span>
          </div>

          <p className="text-xs text-slate-300 leading-relaxed">
            LLM proposed fixes can hallucinate syntax errors or fail to address the core vulnerability. Guardstack runs an isolated sandboxed verification loop:
          </p>

          <div className="space-y-2 text-xs">
            <div className="flex items-center gap-2 text-slate-300">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>Applies proposed diff to an isolated copy in sandbox</span>
            </div>
            <div className="flex items-center gap-2 text-slate-300">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>Validates Python AST syntax integrity</span>
            </div>
            <div className="flex items-center gap-2 text-slate-300">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>Re-runs Semgrep / Gitleaks / Trivy on the patched code</span>
            </div>
            <div className="flex items-center gap-2 text-slate-300">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>Marks fix &ldquo;verified&rdquo; or &ldquo;failed&rdquo; automatically</span>
            </div>
          </div>

          <button
            onClick={() => onNavigateTab('benchmark')}
            className="w-full py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition-colors flex items-center justify-center gap-2"
          >
            <span>View Benchmark Verification Evidence</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Top Actionable Vulnerabilities */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Flame className="w-4 h-4 text-rose-400" />
            <span>Top Actionable PR Blockers</span>
          </h3>
          <button
            onClick={() => onNavigateTab('findings')}
            className="text-xs font-medium text-indigo-400 hover:text-indigo-300 transition-colors flex items-center gap-1"
          >
            <span>View All ({stats.open_findings})</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {topFindings.length === 0 ? (
          <div className="p-12 text-center text-slate-500 glass-panel rounded-2xl">
            No open actionable blockers identified! Trigger a scan to populate findings.
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-3">
            {topFindings.slice(0, 4).map((f) => (
              <div
                key={f.id}
                onClick={() => onSelectFinding(f.id)}
                className="glass-panel p-4 rounded-xl border border-slate-800/80 hover:border-indigo-500/40 hover:bg-[#121a2c]/80 transition-all cursor-pointer flex items-center justify-between gap-4"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 flex flex-col items-center justify-center shrink-0">
                    <span className="text-xs font-black">{f.priority_score}</span>
                    <span className="text-[8px] uppercase font-bold text-slate-400">score</span>
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400">
                        {f.severity}
                      </span>
                      <span className="text-xs font-mono text-slate-400 truncate">{f.file_path}:{f.start_line}</span>
                    </div>
                    <h4 className="text-sm font-semibold text-slate-200 truncate">{f.title}</h4>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {f.analysis?.fix_validated && (
                    <span className="text-[10px] font-semibold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                      Fix Validated
                    </span>
                  )}
                  <ArrowRight className="w-4 h-4 text-slate-500" />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
