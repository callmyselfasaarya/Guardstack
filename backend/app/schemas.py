from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

# --- Repositories ---
class RepositoryBase(BaseModel):
    name: str
    full_name: str
    clone_url: Optional[str] = ""
    default_branch: Optional[str] = "main"

class RepositoryCreate(RepositoryBase):
    pass

class RepositoryResponse(RepositoryBase):
    id: str
    created_at: datetime
    updated_at: datetime
    total_scans: int = 0
    open_findings: int = 0

    class Config:
        from_attributes = True

# --- Analysis & Fix ---
class FindingAnalysisResponse(BaseModel):
    id: str
    finding_id: str
    explanation: str
    attack_scenario: str = ""
    false_positive_likelihood: str = "low"
    confidence: float = 0.85
    proposed_patch: str = ""
    fix_validated: bool = False
    validation_status: str = "untested"  # "verified" | "failed" | "untested"
    validation_details: Optional[Dict[str, Any]] = None
    applied_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True

# --- Findings ---
class FindingResponse(BaseModel):
    id: str
    scan_id: str
    repo_id: str
    fingerprint: str
    tool: str  # semgrep, gitleaks, trivy
    rule_id: str
    title: str
    message: str
    severity: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    cisa_kev: bool = False
    priority_score: float
    file_path: str
    start_line: int
    end_line: int
    code_snippet: str
    status: str  # new, persistent, fixed, regressed
    created_at: datetime
    analysis: Optional[FindingAnalysisResponse] = None

    class Config:
        from_attributes = True

class FindingStatusUpdate(BaseModel):
    status: str = Field(..., description="new, persistent, fixed, false_positive")

# --- Scans ---
class ScanTriggerRequest(BaseModel):
    repo_full_name: str
    target_path_or_url: Optional[str] = None
    commit_hash: Optional[str] = "HEAD"
    branch: Optional[str] = "main"
    pr_number: Optional[int] = None
    scanners: List[str] = Field(default_factory=lambda: ["semgrep", "gitleaks", "trivy"])

class ScanSummaryStats(BaseModel):
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    noise_reduction_pct: float = 0.0
    fixes_validated_pct: float = 0.0
    new_count: int = 0
    persistent_count: int = 0
    fixed_count: int = 0
    regressed_count: int = 0

class ScanResponse(BaseModel):
    id: str
    repo_id: str
    commit_hash: str
    branch: str
    pr_number: Optional[int] = None
    trigger_type: str
    status: str
    scanner_types: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    summary_stats: Optional[Dict[str, Any]] = None
    logs: Optional[str] = ""
    findings_count: int = 0

    class Config:
        from_attributes = True

# --- Webhook Simulation ---
class WebhookSimulatePRRequest(BaseModel):
    repo_full_name: str
    pr_number: int = 42
    title: str = "Feature: Implement user profile and image upload endpoint"
    branch: str = "feature/profile-uploads"
    base_branch: str = "main"
    files_changed: Optional[List[str]] = None
    code_sample_suite: Optional[str] = "vulnerable_web_api"

# --- Benchmark Suite ---
class BenchmarkTriggerRequest(BaseModel):
    suite_name: str = "owasp_top10_corpus"

class BenchmarkRunResponse(BaseModel):
    id: str
    name: str
    test_suite: str
    total_cases: int
    raw_findings_count: int
    filtered_findings_count: int
    noise_reduction_pct: float
    fp_precision: float
    fp_recall: float
    fix_validation_rate: float
    details: Optional[Dict[str, Any]] = None
    created_at: datetime

    class Config:
        from_attributes = True

# --- Settings ---
class AppSettingsResponse(BaseModel):
    llm_provider: str
    has_gemini_key: bool
    has_openai_key: bool
    has_anthropic_key: bool
    ollama_base_url: str
    ollama_model: str
    has_github_app: bool
    github_app_id: str

class AppSettingsUpdate(BaseModel):
    llm_provider: Optional[str] = None
    gemini_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    ollama_base_url: Optional[str] = None
    ollama_model: Optional[str] = None
    github_app_id: Optional[str] = None
    github_webhook_secret: Optional[str] = None
