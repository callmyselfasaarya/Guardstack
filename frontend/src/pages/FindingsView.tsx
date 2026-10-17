import React, { useState } from 'react';
import {
  Search,
  Filter,
  ShieldAlert,
  Flame,
  CheckCircle2
} from 'lucide-react';
import { Finding } from '../types';
import { FindingCard } from '../components/FindingCard';
import { FindingDrawer } from '../components/FindingDrawer';

interface FindingsViewProps {
  findings: Finding[];
  selectedFindingId: string | null;
  onSelectFinding: (id: string | null) => void;
  onRefresh: () => void;
}

export const FindingsView: React.FC<FindingsViewProps> = ({
  findings,
  selectedFindingId,
  onSelectFinding,
  onRefresh,
}) => {
  const [search, setSearch] = useState('');
  const [tool, setTool] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [status, setStatus] = useState('all');
  const [actionableOnly, setActionableOnly] = useState(false);

  const filteredFindings = findings.filter((f) => {
    if (search) {
      const q = search.toLowerCase();
      const match =
        f.title.toLowerCase().includes(q) ||
        f.rule_id.toLowerCase().includes(q) ||
        f.file_path.toLowerCase().includes(q);
      if (!match) return false;
    }
    if (tool !== 'all' && f.tool.toLowerCase() !== tool.toLowerCase()) return false;
    if (severity !== 'all' && f.severity.toUpperCase() !== severity.toUpperCase()) return false;
    if (status !== 'all' && f.status.toLowerCase() !== status.toLowerCase()) return false;
    if (actionableOnly && f.priority_score < 50) return false;
    return true;
  });

  const selectedFinding = findings.find((f) => f.id === selectedFindingId) || null;

  return (
    <div className="space-y-6 animate-in fade-in duration-150">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-indigo-400" />
            <span>Vulnerability Findings</span>
          </h2>
          <p className="text-xs text-slate-400">
            Unified across Semgrep SAST, Gitleaks Secrets, and Trivy SCA with CVSS, EPSS, and CISA KEV scoring
          </p>
        </div>

        {/* Actionable Toggle */}
        <button
          onClick={() => setActionableOnly(!actionableOnly)}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-semibold border transition-all ${
            actionableOnly
              ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 shadow-sm shadow-rose-500/20'
              : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
          }`}
        >
          <Flame className="w-3.5 h-3.5 text-rose-400" />
          <span>Actionable Blockers Only</span>
        </button>
      </div>

      {/* Filter Bar */}
      <div className="glass-panel p-3.5 rounded-2xl flex flex-wrap items-center gap-3">
        {/* Search Input */}
        <div className="relative flex-1 min-w-[200px]">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search by rule, title, or file..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-1.5 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500"
          />
        </div>

        {/* Tool Filter */}
        <select
          value={tool}
          onChange={(e) => setTool(e.target.value)}
          className="px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-300 text-xs focus:outline-none"
        >
          <option value="all">All Scanners</option>
          <option value="semgrep">Semgrep SAST</option>
          <option value="gitleaks">Gitleaks Secrets</option>
          <option value="trivy">Trivy SCA</option>
        </select>

        {/* Severity Filter */}
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-300 text-xs focus:outline-none"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        {/* Status Lifecycle Filter */}
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-300 text-xs focus:outline-none"
        >
          <option value="all">All Statuses</option>
          <option value="new">New in Commit/PR</option>
          <option value="persistent">Persistent across Commits</option>
          <option value="fixed">Fixed</option>
          <option value="regressed">Regressed</option>
        </select>
      </div>

      {/* Findings Count */}
      <div className="flex items-center justify-between text-xs text-slate-400 px-1">
        <span>Showing <strong className="text-white">{filteredFindings.length}</strong> findings</span>
        {actionableOnly && (
          <span className="text-rose-400 text-[11px]">Filtered out non-actionable noise (Risk &lt; 50)</span>
        )}
      </div>

      {/* Findings List */}
      {filteredFindings.length === 0 ? (
        <div className="glass-panel p-12 text-center text-slate-500 rounded-2xl space-y-2">
          <p className="text-sm">No findings match the active filters.</p>
          <button
            onClick={() => { setSearch(''); setTool('all'); setSeverity('all'); setStatus('all'); setActionableOnly(false); }}
            className="text-xs text-indigo-400 hover:underline"
          >
            Reset all filters
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredFindings.map((finding) => (
            <FindingCard
              key={finding.id}
              finding={finding}
              onClick={() => onSelectFinding(finding.id)}
            />
          ))}
        </div>
      )}

      {/* Slide-over Drawer */}
      <FindingDrawer
        finding={selectedFinding}
        onClose={() => onSelectFinding(null)}
        onFindingUpdated={onRefresh}
      />
    </div>
  );
};
