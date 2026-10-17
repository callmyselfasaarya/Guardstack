import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import String, Integer, Float, Boolean, Text, JSON, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), index=True)
    full_name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    clone_url: Mapped[str] = mapped_column(String(1024), default="")
    default_branch: Mapped[str] = mapped_column(String(100), default="main")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    scans: Mapped[List["Scan"]] = relationship("Scan", back_populates="repository", cascade="all, delete-orphan")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="repository", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    repo_id: Mapped[str] = mapped_column(String(36), ForeignKey("repositories.id", ondelete="CASCADE"), index=True)
    commit_hash: Mapped[str] = mapped_column(String(64), index=True, default="HEAD")
    branch: Mapped[str] = mapped_column(String(100), default="main")
    pr_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    trigger_type: Mapped[str] = mapped_column(String(50), default="manual")  # push, pull_request, manual
    status: Mapped[str] = mapped_column(String(50), default="queued")       # queued, running, completed, failed
    scanner_types: Mapped[str] = mapped_column(String(255), default="semgrep,gitleaks,trivy")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    summary_stats: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    logs: Mapped[str] = mapped_column(Text, default="")

    repository: Mapped["Repository"] = relationship("Repository", back_populates="scans")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    repo_id: Mapped[str] = mapped_column(String(36), ForeignKey("repositories.id", ondelete="CASCADE"), index=True)
    
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    tool: Mapped[str] = mapped_column(String(50), index=True)  # semgrep, gitleaks, trivy
    rule_id: Mapped[str] = mapped_column(String(255), index=True)
    title: Mapped[str] = mapped_column(String(500))
    message: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(50), index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    
    # 3-Factor Authoritative Threat Feeds
    cve_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    epss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cisa_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Prioritization Score (0-100)
    priority_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    
    file_path: Mapped[str] = mapped_column(String(1024), index=True)
    start_line: Mapped[int] = mapped_column(Integer, default=1)
    end_line: Mapped[int] = mapped_column(Integer, default=1)
    code_snippet: Mapped[str] = mapped_column(Text, default="")
    
    # Cross-commit lifecycle tracking (new, persistent, fixed, regressed)
    status: Mapped[str] = mapped_column(String(50), default="new", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    
    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
    repository: Mapped["Repository"] = relationship("Repository", back_populates="findings")
    analysis: Mapped[Optional["FindingAnalysis"]] = relationship("FindingAnalysis", back_populates="finding", uselist=False, cascade="all, delete-orphan")

class FindingAnalysis(Base):
    __tablename__ = "finding_analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), unique=True, index=True)
    
    explanation: Mapped[str] = mapped_column(Text)
    attack_scenario: Mapped[str] = mapped_column(Text, default="")
    false_positive_likelihood: Mapped[str] = mapped_column(String(50), default="low")  # low, medium, high
    confidence: Mapped[float] = mapped_column(Float, default=0.85)
    
    proposed_patch: Mapped[str] = mapped_column(Text, default="")
    
    # Fix Validation Loop: "verified" | "failed" | "untested"
    fix_validated: Mapped[bool] = mapped_column(Boolean, default=False)
    validation_status: Mapped[str] = mapped_column(String(50), default="untested")
    validation_details: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    
    applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    finding: Mapped["Finding"] = relationship("Finding", back_populates="analysis")

class BenchmarkRun(Base):
    __tablename__ = "benchmark_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255))
    test_suite: Mapped[str] = mapped_column(String(100), default="owasp_top10_corpus")
    total_cases: Mapped[int] = mapped_column(Integer, default=0)
    raw_findings_count: Mapped[int] = mapped_column(Integer, default=0)
    filtered_findings_count: Mapped[int] = mapped_column(Integer, default=0)
    noise_reduction_pct: Mapped[float] = mapped_column(Float, default=0.0)
    fp_precision: Mapped[float] = mapped_column(Float, default=0.0)
    fp_recall: Mapped[float] = mapped_column(Float, default=0.0)
    fix_validation_rate: Mapped[float] = mapped_column(Float, default=0.0)
    details: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
