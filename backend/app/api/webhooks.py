import json
import logging
from pathlib import Path
from fastapi import APIRouter, Request, Header, HTTPException, Depends, BackgroundTasks
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.scans import run_scan_pipeline
from app.database import get_db
from app.github.webhook_handler import GitHubWebhookHandler
from app.models import Repository, Scan
from app.schemas import WebhookSimulatePRRequest, ScanResponse

logger = logging.getLogger("guardstack.api.webhooks")
router = APIRouter(prefix="", tags=["Webhooks & Simulation"])

@router.post("/webhooks/github")
async def github_webhook_receiver(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: str = Header(default="push"),
    x_hub_signature_256: str = Header(default=None),
    db: AsyncSession = Depends(get_db)
):
    body_bytes = await request.body()
    if not GitHubWebhookHandler.verify_signature(body_bytes, x_hub_signature_256):
        logger.warning("Invalid GitHub webhook signature received.")
        raise HTTPException(status_code=401, detail="Invalid HMAC SHA256 webhook signature.")

    if x_github_event == "ping":
        return {"status": "ok", "message": "Pong from Guardstack Webhook Endpoint."}

    try:
        payload = json.loads(body_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed JSON payload.")

    action, meta = GitHubWebhookHandler.extract_event_metadata(x_github_event, payload)
    if not action:
        return {"status": "ignored", "message": f"Event '{x_github_event}' skipped."}

    # Find or register repo
    repo_name = meta["repo_full_name"].split("/")[-1]
    stmt = select(Repository).where(Repository.full_name == meta["repo_full_name"])
    repo = (await db.execute(stmt)).scalar_one_or_none()
    if not repo:
        repo = Repository(
            name=repo_name,
            full_name=meta["repo_full_name"],
            clone_url=meta.get("clone_url", ""),
            default_branch=meta.get("default_branch", "main")
        )
        db.add(repo)
        await db.commit()
        await db.refresh(repo)

    # Create Scan
    scan = Scan(
        repo_id=repo.id,
        commit_hash=meta.get("commit_hash", "HEAD"),
        branch=meta.get("branch", "main"),
        pr_number=meta.get("pr_number"),
        trigger_type="pull_request" if meta.get("pr_number") else "push",
        status="queued",
        scanner_types="semgrep,gitleaks,trivy"
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Execute scan on corpus or workspace
    target_path = str(Path(__file__).resolve().parent.parent / "benchmark" / "corpus" / "vulnerable_app")
    background_tasks.add_task(
        run_scan_pipeline,
        scan.id,
        repo.id,
        target_path,
        ["semgrep", "gitleaks", "trivy"]
    )

    return {
        "status": "accepted",
        "action": action,
        "scan_id": scan.id,
        "repo": meta["repo_full_name"],
        "pr_number": meta.get("pr_number")
    }

@router.post("/scans/simulate-pr", response_model=ScanResponse)
async def simulate_pr_event(
    payload: WebhookSimulatePRRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    Simulates an incoming Pull Request event without requiring ngrok or live GitHub credentials.
    Runs the full ASPM pipeline and produces findings, risk scores, and PR comments.
    """
    stmt = select(Repository).where(Repository.full_name == payload.repo_full_name)
    repo = (await db.execute(stmt)).scalar_one_or_none()
    if not repo:
        repo = Repository(
            name=payload.repo_full_name.split("/")[-1],
            full_name=payload.repo_full_name,
            clone_url=f"https://github.com/{payload.repo_full_name}.git",
            default_branch=payload.base_branch
        )
        db.add(repo)
        await db.commit()
        await db.refresh(repo)

    scan = Scan(
        repo_id=repo.id,
        commit_hash="c3a4f89d",
        branch=payload.branch,
        pr_number=payload.pr_number,
        trigger_type="pull_request",
        status="queued",
        scanner_types="semgrep,gitleaks,trivy"
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    target_path = str(Path(__file__).resolve().parent.parent / "benchmark" / "corpus" / "vulnerable_app")
    background_tasks.add_task(
        run_scan_pipeline,
        scan.id,
        repo.id,
        target_path,
        ["semgrep", "gitleaks", "trivy"]
    )

    return ScanResponse(
        id=scan.id,
        repo_id=scan.repo_id,
        commit_hash=scan.commit_hash,
        branch=scan.branch,
        pr_number=scan.pr_number,
        trigger_type=scan.trigger_type,
        status=scan.status,
        scanner_types=scan.scanner_types,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        summary_stats={},
        logs=f"Simulated Pull Request #{payload.pr_number}: '{payload.title}' on branch '{payload.branch}'.",
        findings_count=0
    )
