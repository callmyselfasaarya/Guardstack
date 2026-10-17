import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { ScanModal } from './components/ScanModal';
import { DashboardView } from './pages/DashboardView';
import { FindingsView } from './pages/FindingsView';
import { ScansView } from './pages/ScansView';
import { BenchmarkView } from './pages/BenchmarkView';
import { DastView } from './pages/DastView';
import { SettingsView } from './pages/SettingsView';
import {
  fetchOverviewStats,
  fetchRepositories,
  fetchScans,
  fetchFindings,
  fetchSettings
} from './api/client';
import { OverviewStats, Repository, Scan, Finding, AppSettings } from './types';

export function App() {
  const [currentTab, setCurrentTab] = useState<string>('dashboard');
  const [stats, setStats] = useState<OverviewStats | null>(null);
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [scanModalOpen, setScanModalOpen] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    loadAllData();
  }, []);

  const loadAllData = async () => {
    try {
      const [statsData, reposData, scansData, findingsData, settingsData] = await Promise.all([
        fetchOverviewStats().catch(() => null),
        fetchRepositories().catch(() => []),
        fetchScans().catch(() => []),
        fetchFindings().catch(() => []),
        fetchSettings().catch(() => null),
      ]);

      setStats(statsData);
      setRepositories(reposData);
      setScans(scansData);
      setFindings(findingsData);
      setSettings(settingsData);
    } catch (err) {
      console.error('Error loading Guardstack data:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSelectFinding = (findingId: string | null) => {
    setSelectedFindingId(findingId);
    if (findingId) {
      setCurrentTab('findings');
    }
  };

  const handleFilterByScan = (scanId: string) => {
    setCurrentTab('findings');
    fetchFindings({ scan_id: scanId }).then((data) => setFindings(data));
  };

  return (
    <div className="min-h-screen bg-[#0a0e17] text-slate-100 flex flex-col font-sans selection:bg-indigo-500/30 selection:text-indigo-200">
      {/* Top Navbar */}
      <Navbar
        currentTab={currentTab}
        onTabChange={(tab) => {
          setCurrentTab(tab);
          if (tab === 'findings') loadAllData();
        }}
        onOpenScanModal={() => setScanModalOpen(true)}
        postureScore={stats?.posture_score || 100}
        llmProvider={settings?.llm_provider || 'heuristic'}
      />

      {/* Main View Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-8">
        {loading ? (
          <div className="flex flex-col items-center justify-center py-32 space-y-3">
            <div className="w-10 h-10 border-4 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin" />
            <p className="text-xs text-slate-400">Loading Guardstack ASPM Security Platform...</p>
          </div>
        ) : (
          <>
            {currentTab === 'dashboard' && (
              <DashboardView
                stats={stats}
                onNavigateTab={(tab) => setCurrentTab(tab)}
                onOpenScanModal={() => setScanModalOpen(true)}
                onSelectFinding={handleSelectFinding}
                topFindings={findings}
              />
            )}

            {currentTab === 'findings' && (
              <FindingsView
                findings={findings}
                selectedFindingId={selectedFindingId}
                onSelectFinding={handleSelectFinding}
                onRefresh={loadAllData}
              />
            )}

            {currentTab === 'scans' && (
              <ScansView
                repositories={repositories}
                scans={scans}
                onOpenScanModal={() => setScanModalOpen(true)}
                onFilterByScan={handleFilterByScan}
              />
            )}

            {currentTab === 'benchmark' && <BenchmarkView />}

            {currentTab === 'dast' && <DastView />}

            {currentTab === 'settings' && <SettingsView />}
          </>
        )}
      </main>

      {/* Scan Modal */}
      <ScanModal
        isOpen={scanModalOpen}
        onClose={() => setScanModalOpen(false)}
        onScanStarted={() => {
          setTimeout(() => loadAllData(), 1500);
        }}
      />

      {/* Footer */}
      <footer className="border-t border-slate-800/80 py-6 px-6 text-center text-xs text-slate-500 bg-[#070a10]">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>Guardstack ASPM Security Platform • Automated PR Remediation &amp; Risk Prioritization</span>
          <div className="flex items-center gap-4 text-[11px] text-slate-400">
            <span>Semgrep SAST</span>
            <span>•</span>
            <span>Gitleaks</span>
            <span>•</span>
            <span>Trivy SCA</span>
            <span>•</span>
            <span>OWASP ZAP</span>
            <span>•</span>
            <span>Python AST Reachability</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
