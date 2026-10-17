from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.database import get_db
from app.models import Repository, Scan, Finding, FindingAnalysis
from app.schemas import AppSettingsResponse, AppSettingsUpdate

router = APIRouter(prefix="", tags=["Settings & Platform Stats"])

@router.get("/settings", response_model=AppSettingsResponse)
async def get_settings():
    return AppSettingsResponse(
        llm_provider=settings.LLM_PROVIDER,
        has_gemini_key=bool(settings.GEMINI_API_KEY),
        has_openai_key=bool(settings.OPENAI_API_KEY),
        has_anthropic_key=bool(settings.ANTHROPIC_API_KEY),
        ollama_base_url=settings.OLLAMA_BASE_URL,
        ollama_model=settings.OLLAMA_MODEL,
        has_github_app=bool(settings.GITHUB_APP_ID),
        github_app_id=settings.GITHUB_APP_ID
    )

@router.post("/settings", response_model=AppSettingsResponse)
async def update_settings(payload: AppSettingsUpdate):
    if payload.llm_provider:
        settings.LLM_PROVIDER = payload.llm_provider.lower()
    if payload.gemini_api_key is not None:
        settings.GEMINI_API_KEY = payload.gemini_api_key
    if payload.openai_api_key is not None:
        settings.OPENAI_API_KEY = payload.openai_api_key
    if payload.anthropic_api_key is not None:
        settings.ANTHROPIC_API_KEY = payload.anthropic_api_key
    if payload.ollama_base_url is not None:
        settings.OLLAMA_BASE_URL = payload.ollama_base_url
    if payload.ollama_model is not None:
        settings.OLLAMA_MODEL = payload.ollama_model
    if payload.github_app_id is not None:
        settings.GITHUB_APP_ID = payload.github_app_id
    if payload.github_webhook_secret is not None:
        settings.GITHUB_WEBHOOK_SECRET = payload.github_webhook_secret

    return await get_settings()

@router.get("/stats/overview")
async def get_executive_overview(db: AsyncSession = Depends(get_db)):
    """Computes global security posture score and executive ASPM metrics."""
    repo_count = (await db.execute(select(func.count(Repository.id)))).scalar() or 0
    scan_count = (await db.execute(select(func.count(Scan.id)))).scalar() or 0

    open_findings_stmt = select(Finding).where(Finding.status.in_(["new", "persistent", "regressed", "existing"]))
    findings = (await db.execute(open_findings_stmt)).scalars().all()

    total_findings = len(findings)
    crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    med_count = sum(1 for f in findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in findings if f.severity == "LOW")

    actionable_count = sum(1 for f in findings if f.priority_score >= 50.0)

    deductions = (crit_count * 15.0) + (high_count * 8.0) + (med_count * 3.0) + (low_count * 0.5)
    posture_score = round(max(10.0, min(100.0, 100.0 - deductions)), 1) if total_findings > 0 else 100.0

    val_stmt = select(func.count(FindingAnalysis.id)).where(FindingAnalysis.fix_validated == True)
    validated_fixes_count = (await db.execute(val_stmt)).scalar() or 0
    total_analyses_stmt = select(func.count(FindingAnalysis.id))
    total_analyses_count = (await db.execute(total_analyses_stmt)).scalar() or 0
    fix_val_rate = round((validated_fixes_count / total_analyses_count) * 100.0, 1) if total_analyses_count > 0 else 100.0

    noise_reduction_pct = round(((total_findings - actionable_count) / total_findings) * 100.0, 1) if total_findings > 0 else 0.0

    scans_stmt = select(Scan).order_by(Scan.started_at.desc()).limit(5)
    recent_scans = (await db.execute(scans_stmt)).scalars().all()

    return {
        "posture_score": posture_score,
        "total_repositories": repo_count,
        "total_scans": scan_count,
        "open_findings": total_findings,
        "critical_count": crit_count,
        "high_count": high_count,
        "medium_count": med_count,
        "low_count": low_count,
        "actionable_blockers": actionable_count,
        "noise_reduction_pct": noise_reduction_pct,
        "fix_validation_rate": fix_val_rate,
        "recent_scans": [
            {
                "id": s.id,
                "commit": s.commit_hash[:7],
                "branch": s.branch,
                "status": s.status,
                "findings": (s.summary_stats or {}).get("total_findings", 0),
                "started_at": s.started_at.isoformat()
            } for s in recent_scans
        ]
    }
