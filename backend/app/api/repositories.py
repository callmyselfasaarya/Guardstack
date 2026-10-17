from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.models import Repository, Scan, Finding
from app.schemas import RepositoryCreate, RepositoryResponse

router = APIRouter(prefix="/repositories", tags=["Repositories"])

@router.get("", response_model=List[RepositoryResponse])
async def list_repositories(db: AsyncSession = Depends(get_db)):
    stmt = select(Repository).order_by(Repository.created_at.desc())
    result = await db.execute(stmt)
    repos = result.scalars().all()

    response = []
    for r in repos:
        # Count scans
        scan_count_stmt = select(func.count(Scan.id)).where(Scan.repo_id == r.id)
        scans_count = (await db.execute(scan_count_stmt)).scalar() or 0

        # Count open findings
        finding_count_stmt = select(func.count(Finding.id)).where(
            Finding.repo_id == r.id,
            Finding.status.in_(["new", "regressed", "existing"])
        )
        findings_count = (await db.execute(finding_count_stmt)).scalar() or 0

        response.append(RepositoryResponse(
            id=r.id,
            name=r.name,
            full_name=r.full_name,
            clone_url=r.clone_url or "",
            default_branch=r.default_branch,
            created_at=r.created_at,
            updated_at=r.updated_at,
            total_scans=scans_count,
            open_findings=findings_count
        ))
    return response

@router.post("", response_model=RepositoryResponse)
async def create_repository(payload: RepositoryCreate, db: AsyncSession = Depends(get_db)):
    # Check if existing
    stmt = select(Repository).where(Repository.full_name == payload.full_name)
    existing = (await db.execute(stmt)).scalar_one_or_none()
    if existing:
        return RepositoryResponse(
            id=existing.id,
            name=existing.name,
            full_name=existing.full_name,
            clone_url=existing.clone_url,
            default_branch=existing.default_branch,
            created_at=existing.created_at,
            updated_at=existing.updated_at,
            total_scans=0,
            open_findings=0
        )

    repo = Repository(
        name=payload.name,
        full_name=payload.full_name,
        clone_url=payload.clone_url or "",
        default_branch=payload.default_branch or "main"
    )
    db.add(repo)
    await db.commit()
    await db.refresh(repo)

    return RepositoryResponse(
        id=repo.id,
        name=repo.name,
        full_name=repo.full_name,
        clone_url=repo.clone_url,
        default_branch=repo.default_branch,
        created_at=repo.created_at,
        updated_at=repo.updated_at,
        total_scans=0,
        open_findings=0
    )

@router.delete("/{repo_id}")
async def delete_repository(repo_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Repository).where(Repository.id == repo_id)
    repo = (await db.execute(stmt)).scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found.")
    await db.delete(repo)
    await db.commit()
    return {"message": "Repository deleted successfully."}
