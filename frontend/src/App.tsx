import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { ScanModal } from './components/ScanModal';
import { DashboardView } from './pages/DashboardView';
import { FindingsView } from './pages/FindingsView';
import { ScansView } from './pages/ScansView';
import { BenchmarkView } from './pages/BenchmarkView';
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
    <div className="min-h-screen bg-[#0a0e17] text-slate-100 flex flex-col font-sans selection:bg-indigo-500/20 selection:text-indigo-400">
      {/* Navbar */}
      <Navbar
        currentTab={currentTab}
        onTabChange={setCurrentTab}
        onOpenScanModal={() => setScanModalOpen(true)}
        postureScore={stats?.posture_score ?? 100}
        llmProvider={settings?.llm_provider ?? 'heuristic'}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
        {loading ? (
          <div className="flex flex-col items-center justify-center min-h-[400px] space-y-4">
            <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
            <p className="text-xs text-slate-400">Loading Guardstack security telemetry...</p>
          </div>
        ) : (
          <>
            {currentTab === 'dashboard' && (
              <DashboardView
                stats={stats}
                topFindings={findings.slice(0, 5)}
                onSelectFinding={(id: string) => handleSelectFinding(id)}
                onNavigateTab={(tab: string) => setCurrentTab(tab as any)}
                onOpenScanModal={() => setScanModalOpen(true)}
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
            <span>Gitleaks Secrets</span>
            <span>•</span>
            <span>Trivy Dependencies</span>
            <span>•</span>
            <span>CVSS / EPSS / CISA KEV Scoring</span>
            <span>•</span>
            <span>Verified Fix Loop</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
