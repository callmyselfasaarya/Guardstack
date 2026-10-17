import React from 'react';
import {
  ShieldCheck,
  LayoutDashboard,
  ShieldAlert,
  GitBranch,
  BarChart3,
  Globe,
  Settings as SettingsIcon,
  Play,
  Cpu
} from 'lucide-react';

interface NavbarProps {
  currentTab: string;
  onTabChange: (tab: string) => void;
  onOpenScanModal: () => void;
  postureScore: number;
  llmProvider: string;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  onTabChange,
  onOpenScanModal,
  postureScore,
  llmProvider
}) => {
  const tabs = [
    { id: 'dashboard', label: 'Executive ASPM', icon: LayoutDashboard },
    { id: 'findings', label: 'Vulnerabilities', icon: ShieldAlert },
    { id: 'scans', label: 'Repositories & PRs', icon: GitBranch },
    { id: 'benchmark', label: 'Defense Benchmark', icon: BarChart3 },
    { id: 'dast', label: 'DAST Verification', icon: Globe },
    { id: 'settings', label: 'Engine Settings', icon: SettingsIcon },
  ];

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-emerald-400 border-emerald-500/40 bg-emerald-500/10';
    if (score >= 60) return 'text-amber-400 border-amber-500/40 bg-amber-500/10';
    return 'text-rose-400 border-rose-500/40 bg-rose-500/10';
  };

  return (
    <header className="sticky top-0 z-40 border-b border-slate-800/80 bg-[#0a0e17]/90 backdrop-blur-md px-6 py-3.5">
      <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 via-purple-600 to-pink-500 p-0.5 shadow-lg shadow-indigo-500/20">
            <div className="w-full h-full bg-[#0a0e17] rounded-[10px] flex items-center justify-center">
              <ShieldCheck className="w-5 h-5 text-indigo-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-bold text-lg tracking-tight bg-gradient-to-r from-white via-slate-100 to-slate-400 bg-clip-text text-transparent">
                Guardstack
              </h1>
              <span className="text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                ASPM
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              Intelligent Pipeline & Automated PR Remediation
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center gap-1 bg-slate-900/60 p-1 rounded-xl border border-slate-800/80">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const active = currentTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => onTabChange(tab.id)}
                className={`flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-lg transition-all ${
                  active
                    ? 'bg-indigo-600 text-white shadow-sm shadow-indigo-600/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span className="hidden md:inline">{tab.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Action & Status Pills */}
        <div className="flex items-center gap-3">
          {/* Posture Score Pill */}
          <div className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs font-semibold ${getScoreColor(postureScore)}`}>
            <span>Posture:</span>
            <span>{postureScore}%</span>
          </div>

          {/* Active LLM Provider Pill */}
          <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300">
            <Cpu className="w-3.5 h-3.5 text-indigo-400" />
            <span className="text-slate-400">LLM:</span>
            <span className="font-medium capitalize text-slate-200">{llmProvider || 'Heuristic'}</span>
          </div>

          {/* Trigger Scan Button */}
          <button
            onClick={onOpenScanModal}
            className="flex items-center gap-2 px-3.5 py-1.5 bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-400 hover:to-purple-500 text-white text-xs font-semibold rounded-lg shadow-md shadow-indigo-500/25 transition-all"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Trigger Scan</span>
          </button>
        </div>
      </div>
    </header>
  );
};
