import React, { useState, useEffect } from 'react';
import {
  BarChart3,
  ShieldCheck,
  Filter,
  CheckCircle2,
  Play,
  Download,
  AlertTriangle,
  Flame,
  Loader2,
  Check,
  ExternalLink
} from 'lucide-react';
import { BenchmarkRun } from '../types';
import { fetchLatestBenchmark, fetchBenchmarkHistory, runBenchmark } from '../api/client';

export const BenchmarkView: React.FC = () => {
  const [latestRun, setLatestRun] = useState<BenchmarkRun | null>(null);
  const [history, setHistory] = useState<BenchmarkRun[]>([]);
  const [loading, setLoading] = useState(false);
  const [downloaded, setDownloaded] = useState(false);

  useEffect(() => {
    loadBenchmarkData();
  }, []);

  const loadBenchmarkData = async () => {
    try {
      const [latest, hist] = await Promise.all([
        fetchLatestBenchmark(),
        fetchBenchmarkHistory(),
      ]);
      setLatestRun(latest);
      setHistory(hist);
    } catch (err) {
      console.error(err);
    }
  };

  const handleRunBenchmark = async () => {
    setLoading(true);
    try {
      const res = await runBenchmark('owasp_top10_corpus');
      setLatestRun(res);
      await loadBenchmarkData();
    } catch (err) {
      console.error(err);
      alert('Failed to execute benchmark: ' + String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadReport = () => {
    if (!latestRun) return;
    const blob = new Blob([JSON.stringify(latestRun, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `guardstack-defense-benchmark-${latestRun.id.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setDownloaded(true);
    setTimeout(() => setDownloaded(false), 2000);
  };

  const evaluatedFindings = latestRun?.details?.evaluated_findings || [];

  return (
    <div className="space-y-8 animate-in fade-in duration-150">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/20 mb-2">
            Defense & Evaluation Suite
          </div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-purple-400" />
            <span>Defensible Benchmark & Accuracy Metrics</span>
          </h2>
          <p className="text-xs text-slate-400">
            Empirical measurements evaluated against intentionally vulnerable test corpus (OWASP Juice Shop / DVWA patterns)
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={handleDownloadReport}
            disabled={!latestRun}
            className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors"
          >
            {downloaded ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Download className="w-3.5 h-3.5" />}
            <span>Export Audit JSON</span>
          </button>
          <button
            onClick={handleRunBenchmark}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-purple-500 to-indigo-600 hover:from-purple-400 hover:to-indigo-500 disabled:opacity-50 text-white text-xs font-bold rounded-xl shadow-lg shadow-purple-500/20 transition-all"
          >
            {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
            <span>{loading ? 'Evaluating...' : 'Run Live Benchmark'}</span>
          </button>
        </div>
      </div>

      {/* Core Defensibility Numbers */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Noise Reduction */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800 space-y-2 relative overflow-hidden group hover:border-emerald-500/40 transition-all">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Developer Noise Reduction</span>
            <Filter className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-3xl font-extrabold text-emerald-400 tracking-tight">
            {latestRun ? `${latestRun.noise_reduction_pct}%` : '--'}
          </div>
          <p className="text-[11px] text-slate-400">
            Suppressed non-reachable & low-risk warnings that developers don't have to read.
          </p>
        </div>

        {/* Metric 2: Patch Validation Pass Rate */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800 space-y-2 relative overflow-hidden group hover:border-purple-500/40 transition-all">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Patch Validation Pass Rate</span>
            <CheckCircle2 className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-3xl font-extrabold text-purple-400 tracking-tight">
            {latestRun ? `${latestRun.fix_validation_rate}%` : '--'}
          </div>
          <p className="text-[11px] text-slate-400">
            Percentage of AI proposed diffs verified clean upon automated re-scan.
          </p>
        </div>

        {/* Metric 3: AI False-Positive Precision */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800 space-y-2 relative overflow-hidden group hover:border-indigo-500/40 transition-all">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>AI Filter Precision</span>
            <ShieldCheck className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-3xl font-extrabold text-indigo-400 tracking-tight">
            {latestRun ? `${(latestRun.fp_precision * 100).toFixed(1)}%` : '--'}
          </div>
          <p className="text-[11px] text-slate-400">
            Accuracy of flagged findings vs ground-truth true vulnerabilities.
          </p>
        </div>

        {/* Metric 4: Recall Rate */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800 space-y-2 relative overflow-hidden group hover:border-cyan-500/40 transition-all">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Vulnerability Recall</span>
            <Flame className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-3xl font-extrabold text-cyan-400 tracking-tight">
            {latestRun ? `${(latestRun.fp_recall * 100).toFixed(1)}%` : '--'}
          </div>
          <p className="text-[11px] text-slate-400">
            Identified real high-impact exploits without missing critical risks.
          </p>
        </div>
      </div>

      {/* Comparison: Raw Scanner Output vs Guardstack Prioritized */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-slate-500" />
              <span>Raw Unfiltered Scanners</span>
            </h3>
            <span className="text-xs font-mono text-slate-400">
              {latestRun?.raw_findings_count || 0} alerts
            </span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Raw tools (Semgrep, Gitleaks, Trivy) treat every pattern match equally, inundating developer PRs with dead code warnings and unexploitable internal helpers.
          </p>
          <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2 text-xs">
            <div className="flex justify-between">
              <span className="text-slate-400">Developer Cognitive Load:</span>
              <span className="text-rose-400 font-semibold">High (Severe Alert Fatigue)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Fix Verification:</span>
              <span className="text-slate-400">None (Developer must manually test)</span>
            </div>
          </div>
        </div>

        <div className="glass-panel p-6 rounded-2xl border border-indigo-500/30 bg-indigo-950/10 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
              <span>Guardstack Prioritized &amp; Validated</span>
            </h3>
            <span className="text-xs font-mono text-emerald-400 font-bold">
              {latestRun?.filtered_findings_count || 0} actionable blockers
            </span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Prioritizes findings using CVSS, EPSS, and CISA KEV feeds. Validates fixes with a sandboxed re-scan loop before posting to PR.
          </p>
          <div className="p-3.5 rounded-xl bg-indigo-950/40 border border-indigo-500/30 space-y-2 text-xs">
            <div className="flex justify-between">
              <span className="text-slate-300">Developer Reading Load:</span>
              <span className="text-emerald-400 font-semibold">Reduced by {latestRun?.noise_reduction_pct || 0}%</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-300">Verified Fix Guarantee:</span>
              <span className="text-purple-300 font-semibold">100% Re-scan Validated</span>
            </div>
          </div>
        </div>
      </div>

      {/* Ground-Truth Evaluation Matrix */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
          Benchmark Ground-Truth Evaluation Matrix
        </h3>

        {evaluatedFindings.length === 0 ? (
          <div className="glass-panel p-8 text-center text-slate-500 rounded-2xl">
            Click 'Run Live Benchmark' to populate the ground-truth comparison table.
          </div>
        ) : (
          <div className="glass-panel rounded-2xl border border-slate-800 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800 font-medium">
                  <tr>
                    <th className="py-3 px-4">Test Finding</th>
                    <th className="py-3 px-4">Scanner</th>
                    <th className="py-3 px-4">Severity & CVSS</th>
                    <th className="py-3 px-4">EPSS & KEV Feeds</th>
                    <th className="py-3 px-4">Risk Score</th>
                    <th className="py-3 px-4">Actionable Blocker</th>
                    <th className="py-3 px-4">Re-Scan Fix Validation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300 font-mono text-[11px]">
                  {evaluatedFindings.map((item: any, idx: number) => (
                    <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-4 font-sans font-medium text-slate-200">
                        <div>{item.title}</div>
                        <div className="text-[10px] text-slate-400 font-mono">{item.file_path}:{item.start_line}</div>
                      </td>
                      <td className="py-3 px-4 uppercase text-slate-400">{item.tool}</td>
                      <td className="py-3 px-4 font-sans">
                        <span className="font-semibold text-rose-300">{item.severity}</span>
                      </td>
                      <td className="py-3 px-4 font-sans">
                        {item.cisa_kev ? (
                          <span className="text-rose-400 font-semibold block">⚠️ CISA KEV ({(item.epss * 100).toFixed(0)}% EPSS)</span>
                        ) : (
                          <span className="text-slate-400 font-sans block">{item.epss ? (item.epss * 100).toFixed(0) : '< 5'}% EPSS</span>
                        )}
                      </td>
                      <td className="py-3 px-4 font-bold text-white">
                        {item.priority_score} / 100
                      </td>
                      <td className="py-3 px-4 font-sans">
                        {item.is_actionable ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                            PR Blocker
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-400">
                            Suppressed Noise
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 font-sans">
                        {item.fix_validated ? (
                          <span className="inline-flex items-center gap-1 text-emerald-400 font-semibold text-[11px]">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            Pass (Clean)
                          </span>
                        ) : (
                          <span className="text-slate-500">N/A</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
