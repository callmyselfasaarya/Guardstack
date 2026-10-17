export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type PriorityTier = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type FindingStatus = 'new' | 'existing' | 'fixed' | 'regressed' | 'accepted' | 'false_positive';
export type ToolName = 'semgrep' | 'gitleaks' | 'trivy' | 'zap';

export interface Repository {
  id: string;
  name: string;
  full_name: string;
  clone_url: string;
  default_branch: string;
  created_at: string;
  updated_at: string;
  total_scans: number;
  open_findings: number;
}

export interface FindingAnalysis {
  id: string;
  finding_id: string;
  explanation: string;
  attack_scenario: string;
  false_positive_likelihood: 'low' | 'medium' | 'high';
  confidence: number;
  proposed_patch: string;
  fix_validated: boolean;
  validation_details?: {
    re_scan_clean?: boolean;
    syntax_valid?: boolean;
    message?: string;
    timestamp?: string;
  };
  applied_at?: string;
  created_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  repo_id: string;
  fingerprint: string;
  tool: ToolName;
  rule_id: string;
  title: string;
  message: string;
  severity: Severity;
  cve_id?: string;
  cvss_score?: number;
  epss_score?: number;
  cisa_kev: boolean;
  reachability_status: 'reachable' | 'unreachable' | 'unknown';
  reachability_trace?: {
    chain?: string[];
    entrypoint?: string;
    reachability_type?: string;
    reason?: string;
  };
  exposure_status: 'public_route' | 'internal_only' | 'unknown';
  priority_score: number;
  file_path: string;
  start_line: number;
  end_line: number;
  code_snippet: string;
  status: FindingStatus;
  created_at: string;
  analysis?: FindingAnalysis;
}

export interface Scan {
  id: string;
  repo_id: string;
  commit_hash: string;
  branch: string;
  pr_number?: number;
  trigger_type: 'push' | 'pull_request' | 'manual' | 'dast' | 'benchmark';
  status: 'queued' | 'running' | 'completed' | 'failed';
  scanner_types: string;
  started_at: string;
  completed_at?: string;
  summary_stats?: {
    total_findings?: number;
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    actionable_count?: number;
    noise_reduction_pct?: number;
    fixes_validated_pct?: number;
    validated_fixes_count?: number;
  };
  logs?: string;
  findings_count: number;
}

export interface OverviewStats {
  posture_score: number;
  total_repositories: number;
  total_scans: number;
  open_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  actionable_blockers: number;
  noise_reduction_pct: number;
  fix_validation_rate: number;
  recent_scans: {
    id: string;
    commit: string;
    branch: string;
    status: string;
    findings: number;
    started_at: string;
  }[];
}

export interface BenchmarkRun {
  id: string;
  name: string;
  test_suite: string;
  total_cases: number;
  raw_findings_count: number;
  filtered_findings_count: number;
  noise_reduction_pct: number;
  fp_precision: number;
  fp_recall: number;
  fix_validation_rate: number;
  details?: {
    noise_filtered_count?: number;
    validated_patches_count?: number;
    evaluated_findings?: any[];
  };
  created_at: string;
}

export interface DASTTarget {
  id: string;
  url: string;
  verification_token: string;
  verified: boolean;
  verified_at?: string;
  last_scanned_at?: string;
  created_at: string;
}

export interface AppSettings {
  llm_provider: string;
  has_gemini_key: boolean;
  has_openai_key: boolean;
  has_anthropic_key: boolean;
  ollama_base_url: string;
  ollama_model: string;
  has_github_app: boolean;
  github_app_id: string;
  dast_allow_localhost: boolean;
}
