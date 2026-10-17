import React, { useState } from 'react';
import {
  GitBranch,
  FolderGit2,
  GitPullRequest,
  CheckCircle2,
  Clock,
  AlertCircle,
  Play,
  Terminal
} from 'lucide-react';
import { Repository, Scan } from '../types';

interface ScansViewProps {
  repositories: Repository[];
  scans: Scan[];
  onOpenScanModal: () => void;
  onFilterByScan: (scanId: string) => void;
}
  
export const ScansView: React.FC<ScansViewProps> = ({
  repositories,
  scans,
  onOpenScanModal,
  onFilterByScan,
}) => {
  const [selectedScanLogs, setSelectedScanLogs] = useState<Scan | null>(null);

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
            <CheckCircle2 className="w-3 h-3" />
            Completed
          </span>
        );
      case 'running':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20 animate-pulse">
            <Clock className="w-3 h-3" />
            Running
          </span>
        );
      case 'failed':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-rose-400 bg-rose-500/10 px-2 py-0.5 rounded border border-rose-500/20">
            <AlertCircle className="w-3 h-3" />
            Failed
          </span>
        );
      default:
        return (
          <span className="text-[11px] text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
            {status}
          </span>
        );
    }
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-150">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <GitBranch className="w-5 h-5 text-indigo-400" />
            <span>Repositories & Pull Request Scans</span>
          </h2>
          <p className="text-xs text-slate-400">
            Pipeline trigger history across GitHub push, PR webhooks, and manual evaluations
          </p>
        </div>

        <button
          onClick={onOpenScanModal}
          className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-400 hover:to-purple-500 text-white text-xs font-semibold rounded-xl shadow-lg shadow-indigo-500/20 transition-all"
        >
          <Play className="w-3.5 h-3.5 fill-current" />
          <span>Launch Scan / Simulate PR</span>
        </button>
      </div>

      {/* Repositories Section */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
          <FolderGit2 className="w-4 h-4 text-indigo-400" />
          <span>Tracked Repositories</span>
        </h3>

        {repositories.length === 0 ? (
          <div className="glass-panel p-8 text-center text-slate-500 rounded-2xl">
            No repositories registered yet. Launch a scan to track your first repo.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {repositories.map((repo) => (
              <div key={repo.id} className="glass-panel p-5 rounded-2xl border border-slate-800 space-y-3">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h4 className="text-sm font-bold text-white truncate">{repo.full_name}</h4>
                    <span className="text-[11px] text-slate-400 font-mono">branch: {repo.default_branch}</span>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                    Active
                  </span>
                </div>

                <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 text-xs">
                  <span className="text-slate-400">{repo.total_scans} Scans</span>
                  <span className="font-semibold text-rose-400">{repo.open_findings} Open Findings</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Scans Execution Feed */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
          <Clock className="w-4 h-4 text-purple-400" />
          <span>Recent Scan Executions</span>
        </h3>

        {scans.length === 0 ? (
          <div className="glass-panel p-8 text-center text-slate-500 rounded-2xl">
            No scan history recorded.
          </div>
        ) : (
          <div className="glass-panel rounded-2xl border border-slate-800 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800 font-medium">
                  <tr>
                    <th className="py-3 px-4">Trigger / Event</th>
                    <th className="py-3 px-4">Commit & Branch</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Findings Found</th>
                    <th className="py-3 px-4">Executed Scanners</th>
                    <th className="py-3 px-4">Timestamp</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {scans.map((scan) => (
                    <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-4 font-semibold text-white">
                        <div className="flex items-center gap-2">
                          {scan.trigger_type === 'pull_request' ? (
                            <span className="inline-flex items-center gap-1 text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded text-[11px]">
                              <GitPullRequest className="w-3 h-3" />
                              PR #{scan.pr_number || 42}
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-slate-400 bg-slate-800 px-2 py-0.5 rounded text-[11px] uppercase">
                              {scan.trigger_type}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px]">
                        <span className="text-indigo-300">{scan.commit_hash.slice(0, 7)}</span> on{' '}
                        <span className="text-slate-400">{scan.branch}</span>
                      </td>
                      <td className="py-3 px-4">{getStatusBadge(scan.status)}</td>
                      <td className="py-3 px-4 font-bold text-white">
                        {scan.findings_count} findings
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">
                        {scan.scanner_types}
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">
                        {new Date(scan.started_at).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 text-right space-x-2">
                        {scan.logs && (
                          <button
                            onClick={() => setSelectedScanLogs(scan)}
                            className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
                            title="View Scan Logs"
                          >
                            <Terminal className="w-4 h-4" />
                          </button>
                        )}
                        <button
                          onClick={() => onFilterByScan(scan.id)}
                          className="text-xs text-indigo-400 hover:underline font-medium"
                        >
                          View Findings
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Logs Modal */}
      {selectedScanLogs && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in">
          <div className="bg-[#0e1626] border border-slate-700 w-full max-w-2xl rounded-2xl shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Terminal className="w-4 h-4 text-indigo-400" />
                <span>Scan Execution Logs ({selectedScanLogs.commit_hash.slice(0, 7)})</span>
              </h3>
              <button
                onClick={() => setSelectedScanLogs(null)}
                className="text-slate-400 hover:text-white"
              >
                &times;
              </button>
            </div>
            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 whitespace-pre-wrap max-h-80 overflow-y-auto">
              {selectedScanLogs.logs}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
