import React, { useState } from 'react';
import { X, Play, GitPullRequest, Folder, Globe, Loader2 } from 'lucide-react';
import { triggerScan, simulatePR } from '../api/client';

interface ScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onScanStarted: () => void;
}

export const ScanModal: React.FC<ScanModalProps> = ({ isOpen, onClose, onScanStarted }) => {
  const [mode, setMode] = useState<'local' | 'simulate_pr' | 'git_url'>('simulate_pr');
  const [repoName, setRepoName] = useState('guardstack-org/core-api');
  const [targetPath, setTargetPath] = useState('');
  const [prNumber, setPrNumber] = useState(42);
  const [prTitle, setPrTitle] = useState('Feature: Image uploads & user profile search');
  const [branch, setBranch] = useState('feature/profile-uploads');
  const [semgrep, setSemgrep] = useState(true);
  const [gitleaks, setGitleaks] = useState(true);
  const [trivy, setTrivy] = useState(true);
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const scanners = [];
      if (semgrep) scanners.push('semgrep');
      if (gitleaks) scanners.push('gitleaks');
      if (trivy) scanners.push('trivy');

      if (mode === 'simulate_pr') {
        await simulatePR({
          repo_full_name: repoName,
          pr_number: prNumber,
          title: prTitle,
          branch: branch,
        });
      } else {
        await triggerScan({
          repo_full_name: repoName,
          target_path_or_url: targetPath || undefined,
          branch: branch,
          scanners: scanners,
        });
      }
      onScanStarted();
      onClose();
    } catch (err) {
      console.error(err);
      alert('Failed to trigger scan: ' + String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-[#0e1626] border border-slate-700/80 w-full max-w-lg rounded-2xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/60">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-indigo-500/20 text-indigo-400 flex items-center justify-center border border-indigo-500/30">
              <Play className="w-4 h-4 fill-current" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-white">Trigger Security Pipeline</h2>
              <p className="text-xs text-slate-400">Run scanners, risk prioritization & fix validation</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {/* Mode Selector */}
          <div className="grid grid-cols-3 gap-2 p-1 bg-slate-900/80 rounded-xl border border-slate-800 text-xs">
            <button
              type="button"
              onClick={() => setMode('simulate_pr')}
              className={`flex items-center justify-center gap-1.5 py-2 rounded-lg font-medium transition-all ${
                mode === 'simulate_pr'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <GitPullRequest className="w-3.5 h-3.5" />
              <span>Simulate PR</span>
            </button>
            <button
              type="button"
              onClick={() => setMode('local')}
              className={`flex items-center justify-center gap-1.5 py-2 rounded-lg font-medium transition-all ${
                mode === 'local'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Folder className="w-3.5 h-3.5" />
              <span>Local / Demo</span>
            </button>
            <button
              type="button"
              onClick={() => setMode('git_url')}
              className={`flex items-center justify-center gap-1.5 py-2 rounded-lg font-medium transition-all ${
                mode === 'git_url'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              <span>Git Clone URL</span>
            </button>
          </div>

          {/* Repo Name */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">Repository Identifier</label>
            <input
              type="text"
              value={repoName}
              onChange={(e) => setRepoName(e.target.value)}
              className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-indigo-500"
              required
            />
          </div>

          {/* Mode Specific Inputs */}
          {mode === 'simulate_pr' && (
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">PR Number</label>
                <input
                  type="number"
                  value={prNumber}
                  onChange={(e) => setPrNumber(Number(e.target.value))}
                  className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-indigo-500"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Feature Branch</label>
                <input
                  type="text"
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-indigo-500"
                />
              </div>
              <div className="col-span-2 space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Pull Request Title</label>
                <input
                  type="text"
                  value={prTitle}
                  onChange={(e) => setPrTitle(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-indigo-500"
                />
              </div>
            </div>
          )}

          {mode === 'local' && (
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-300">Target Folder Path (optional)</label>
              <input
                type="text"
                placeholder="Leave blank to scan curated benchmark corpus"
                value={targetPath}
                onChange={(e) => setTargetPath(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-indigo-500"
              />
              <p className="text-[11px] text-slate-400">Defaults to the bundled vulnerable application suite.</p>
            </div>
          )}

          {mode === 'git_url' && (
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-300">Remote Git URL</label>
              <input
                type="text"
                placeholder="https://github.com/owner/repository.git"
                value={targetPath}
                onChange={(e) => setTargetPath(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-indigo-500"
              />
            </div>
          )}

          {/* Scanner Checklist */}
          <div className="space-y-2 pt-1">
            <label className="text-xs font-medium text-slate-300">Active Scanner Engines</label>
            <div className="grid grid-cols-3 gap-2">
              <label className="flex items-center gap-2 p-2.5 rounded-xl border border-slate-800 bg-slate-900 text-xs text-slate-300 cursor-pointer hover:border-slate-700">
                <input
                  type="checkbox"
                  checked={semgrep}
                  onChange={(e) => setSemgrep(e.target.checked)}
                  className="rounded text-indigo-600 focus:ring-0"
                />
                <span>Semgrep SAST</span>
              </label>
              <label className="flex items-center gap-2 p-2.5 rounded-xl border border-slate-800 bg-slate-900 text-xs text-slate-300 cursor-pointer hover:border-slate-700">
                <input
                  type="checkbox"
                  checked={gitleaks}
                  onChange={(e) => setGitleaks(e.target.checked)}
                  className="rounded text-indigo-600 focus:ring-0"
                />
                <span>Gitleaks Secrets</span>
              </label>
              <label className="flex items-center gap-2 p-2.5 rounded-xl border border-slate-800 bg-slate-900 text-xs text-slate-300 cursor-pointer hover:border-slate-700">
                <input
                  type="checkbox"
                  checked={trivy}
                  onChange={(e) => setTrivy(e.target.checked)}
                  className="rounded text-indigo-600 focus:ring-0"
                />
                <span>Trivy SCA</span>
              </label>
            </div>
          </div>

          {/* Submit */}
          <div className="pt-2">
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-400 hover:to-purple-500 disabled:opacity-50 text-white text-xs font-semibold rounded-xl shadow-lg shadow-indigo-500/20 transition-all flex items-center justify-center gap-2"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-current" />}
              <span>{loading ? 'Initiating Scan...' : 'Launch Security Pipeline'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
