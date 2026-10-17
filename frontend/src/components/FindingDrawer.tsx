import React, { useState } from 'react';
import {
  X,
  ShieldCheck,
  ShieldAlert,
  GitPullRequest,
  CheckCircle2,
  RefreshCw,
  ExternalLink,
  Flame,
  AlertOctagon,
  FileCode,
  Radio
} from 'lucide-react';
import { Finding } from '../types';
import { DiffViewer } from './DiffViewer';
import { CallGraphViewer } from './CallGraphViewer';
import { PRCommentModal } from './PRCommentModal';
import { updateFindingStatus, revalidateFix } from '../api/client';

interface FindingDrawerProps {
  finding: Finding | null;
  onClose: () => void;
  onFindingUpdated: () => void;
}

export const FindingDrawer: React.FC<FindingDrawerProps> = ({
  finding,
  onClose,
  onFindingUpdated,
}) => {
  const [prModalOpen, setPrModalOpen] = useState(false);
  const [validating, setValidating] = useState(false);
  const [statusUpdating, setStatusUpdating] = useState(false);

  if (!finding) return null;

  const handleStatusChange = async (newStatus: string) => {
    setStatusUpdating(true);
    try {
      await updateFindingStatus(finding.id, newStatus);
      onFindingUpdated();
    } catch (err) {
      console.error(err);
      alert('Failed to update status');
    } finally {
      setStatusUpdating(false);
    }
  };

  const handleRevalidate = async () => {
    setValidating(true);
    try {
      const res = await revalidateFix(finding.id);
      alert(res.details?.message || (res.fix_validated ? 'Fix verified clean!' : 'Fix validation failed.'));
      onFindingUpdated();
    } catch (err) {
      console.error(err);
      alert('Validation request failed: ' + String(err));
    } finally {
      setValidating(false);
    }
  };

  const analysis = finding.analysis;
  const isFixValidated = analysis?.fix_validated;

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm animate-in fade-in" onClick={onClose} />
      <div className="fixed inset-y-0 right-0 z-50 w-full max-w-2xl bg-[#0c121e] border-l border-slate-800 shadow-2xl flex flex-col overflow-hidden animate-in slide-in-from-right duration-200">
        {/* Header */}
        <div className="p-6 border-b border-slate-800/80 bg-slate-900/50 flex items-start justify-between gap-4">
          <div className="space-y-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                {finding.severity}
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                Score: {finding.priority_score} / 100
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono text-slate-400 bg-slate-800">
                {finding.rule_id}
              </span>
            </div>
            <h2 className="text-base font-bold text-white pt-1">{finding.title}</h2>
            <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
              <FileCode className="w-3.5 h-3.5 text-indigo-400" />
              <span>{finding.file_path}:{finding.start_line}</span>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Threat Intelligence Matrix */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400">CVSS v3</span>
              <div className="text-base font-bold text-white">
                {finding.cvss_score ? `${finding.cvss_score} / 10` : 'N/A'}
              </div>
              <p className="text-[10px] text-slate-400">Base severity</p>
            </div>
            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400">EPSS Likelihood</span>
              <div className="text-base font-bold text-emerald-400">
                {finding.epss_score !== undefined ? `${(finding.epss_score * 100).toFixed(1)}%` : '< 5%'}
              </div>
              <p className="text-[10px] text-slate-400">30-day exploit prob.</p>
            </div>
            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400">CISA KEV</span>
              <div className={`text-base font-bold ${finding.cisa_kev ? 'text-rose-400' : 'text-slate-400'}`}>
                {finding.cisa_kev ? 'ACTIVE ⚠️' : 'Not Listed'}
              </div>
              <p className="text-[10px] text-slate-400">Known exploited</p>
            </div>
            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400">Public Route</span>
              <div className="text-base font-bold text-cyan-400 capitalize">
                {finding.exposure_status === 'public_route' ? 'Exposed' : 'Internal'}
              </div>
              <p className="text-[10px] text-slate-400">Network exposure</p>
            </div>
          </div>

          {/* Call Graph Reachability */}
          <CallGraphViewer
            status={finding.reachability_status}
            trace={finding.reachability_trace}
          />

          {/* Vulnerable Code Snippet */}
          <div className="space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Vulnerable Code Snippet
            </h3>
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-rose-300 overflow-x-auto whitespace-pre">
              {finding.code_snippet}
            </div>
          </div>

          {/* AI Security Explanation */}
          <div className="space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              AI Vulnerability Explanation
            </h3>
            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 text-xs text-slate-200 leading-relaxed">
              {analysis?.explanation || finding.message}
            </div>
          </div>

          {/* Step-by-Step Attack Scenario */}
          {analysis?.attack_scenario && (
            <div className="space-y-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Flame className="w-3.5 h-3.5 text-rose-400" />
                <span>Hypothetical Attack Scenario</span>
              </h3>
              <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-500/20 text-xs text-slate-300 leading-relaxed whitespace-pre-line font-sans">
                {analysis.attack_scenario}
              </div>
            </div>
          )}

          {/* Proposed Fix Diff */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                AI-Generated Remediation Patch
              </h3>
              {isFixValidated ? (
                <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Validated by Re-scan
                </span>
              ) : (
                <span className="text-[11px] text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
                  Pending Sandbox Re-scan
                </span>
              )}
            </div>

            <DiffViewer
              diff={analysis?.proposed_patch || ''}
              filePath={finding.file_path}
            />

            {/* Fix Validation Note */}
            <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-300 space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-white">Automated Sandbox Fix Verification:</span>
                <button
                  onClick={handleRevalidate}
                  disabled={validating}
                  className="flex items-center gap-1 px-2.5 py-1 rounded bg-indigo-600/30 hover:bg-indigo-600/50 text-indigo-300 border border-indigo-500/30 text-[11px] font-medium transition-colors"
                >
                  <RefreshCw className={`w-3 h-3 ${validating ? 'animate-spin' : ''}`} />
                  <span>{validating ? 'Re-scanning...' : 'Re-scan Sandbox'}</span>
                </button>
              </div>
              <p className="text-[11px] text-slate-400">
                {analysis?.validation_details?.message ||
                  'Guardstack tests proposed diffs in an isolated temporary sandbox to confirm the scanner finding is 100% eliminated.'}
              </p>
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="p-5 border-t border-slate-800 bg-slate-900/90 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <select
              value={finding.status}
              disabled={statusUpdating}
              onChange={(e) => handleStatusChange(e.target.value)}
              className="px-3 py-1.5 rounded-xl bg-slate-800 border border-slate-700 text-slate-200 text-xs focus:outline-none"
            >
              <option value="new">Status: New</option>
              <option value="accepted">Status: Accepted Risk</option>
              <option value="false_positive">Status: False Positive</option>
              <option value="fixed">Status: Fixed</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setPrModalOpen(true)}
              className="flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors"
            >
              <GitPullRequest className="w-3.5 h-3.5 text-indigo-400" />
              <span>Preview GitHub PR Comment</span>
            </button>
          </div>
        </div>
      </div>

      {/* PR Comment Simulation Modal */}
      {prModalOpen && (
        <PRCommentModal
          findingId={finding.id}
          onClose={() => setPrModalOpen(false)}
        />
      )}
    </>
  );
};
