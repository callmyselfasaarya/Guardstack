import type {
  OverviewStats,
  Repository,
  Scan,
  Finding,
  BenchmarkRun,
  AppSettings
} from '../types';

const API_BASE = '/api';

export async function fetchOverviewStats(): Promise<OverviewStats> {
  const res = await fetch(`${API_BASE}/stats/overview`);
  if (!res.ok) throw new Error('Failed to fetch overview stats');
  return res.json();
}

export async function fetchRepositories(): Promise<Repository[]> {
  const res = await fetch(`${API_BASE}/repositories`);
  if (!res.ok) throw new Error('Failed to fetch repositories');
  return res.json();
}

export async function createRepository(data: { name: string; full_name: string; clone_url?: string }): Promise<Repository> {
  const res = await fetch(`${API_BASE}/repositories`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to create repository');
  return res.json();
}

export async function fetchScans(repoId?: string): Promise<Scan[]> {
  const url = repoId ? `${API_BASE}/scans?repo_id=${repoId}` : `${API_BASE}/scans`;
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to fetch scans');
  return res.json();
}

export async function triggerScan(data: {
  repo_full_name: string;
  target_path_or_url?: string;
  branch?: string;
  scanners?: string[];
}): Promise<Scan> {
  const res = await fetch(`${API_BASE}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to trigger scan');
  return res.json();
}

export async function simulatePR(data: {
  repo_full_name: string;
  pr_number?: number;
  title?: string;
  branch?: string;
}): Promise<Scan> {
  const res = await fetch(`${API_BASE}/scans/simulate-pr`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to simulate PR event');
  return res.json();
}

export async function fetchFindings(params?: Record<string, string>): Promise<Finding[]> {
  const query = params ? '?' + new URLSearchParams(params).toString() : '';
  const res = await fetch(`${API_BASE}/findings${query}`);
  if (!res.ok) throw new Error('Failed to fetch findings');
  return res.json();
}

export async function fetchFinding(id: string): Promise<Finding> {
  const res = await fetch(`${API_BASE}/findings/${id}`);
  if (!res.ok) throw new Error('Failed to fetch finding');
  return res.json();
}

export async function updateFindingStatus(id: string, status: string): Promise<Finding> {
  const res = await fetch(`${API_BASE}/findings/${id}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  });
  if (!res.ok) throw new Error('Failed to update finding status');
  return res.json();
}

export async function fetchPRCommentPreview(id: string): Promise<{ finding_id: string; markdown: string }> {
  const res = await fetch(`${API_BASE}/findings/${id}/pr-comment-preview`);
  if (!res.ok) throw new Error('Failed to fetch PR comment preview');
  return res.json();
}

export async function validateFindingFix(id: string) {
  const res = await fetch(`${API_BASE}/findings/${id}/validate-fix`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error('Failed to re-validate fix');
  return res.json();
}

export async function fetchLatestBenchmark(): Promise<BenchmarkRun> {
  const res = await fetch(`${API_BASE}/benchmark/latest`);
  if (!res.ok) throw new Error('Failed to fetch benchmark');
  return res.json();
}

export async function fetchBenchmarkHistory(): Promise<BenchmarkRun[]> {
  const res = await fetch(`${API_BASE}/benchmark/history`);
  if (!res.ok) throw new Error('Failed to fetch benchmark history');
  return res.json();
}

export async function runBenchmark(suiteName: string = 'owasp_top10_corpus'): Promise<BenchmarkRun> {
  const res = await fetch(`${API_BASE}/benchmark/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ suite_name: suiteName }),
  });
  if (!res.ok) throw new Error('Failed to run benchmark');
  return res.json();
}

export async function fetchSettings(): Promise<AppSettings> {
  const res = await fetch(`${API_BASE}/settings`);
  if (!res.ok) throw new Error('Failed to fetch settings');
  return res.json();
}

export async function updateSettings(data: Partial<AppSettings>): Promise<AppSettings> {
  const res = await fetch(`${API_BASE}/settings`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to update settings');
  return res.json();
}
