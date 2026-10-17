from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from app.benchmark.runner import BenchmarkSuiteRunner
from app.database import get_db
from app.models import BenchmarkRun
from app.schemas import BenchmarkTriggerRequest, BenchmarkRunResponse

router = APIRouter(prefix="/benchmark", tags=["Benchmark & Evaluation"])

@router.post("/run", response_model=BenchmarkRunResponse)
async def execute_benchmark(payload: BenchmarkTriggerRequest, db: AsyncSession = Depends(get_db)):
    result = await BenchmarkSuiteRunner.run_benchmark(suite_name=payload.suite_name)

    run_record = BenchmarkRun(
        name=result["name"],
        test_suite=result["test_suite"],
        total_cases=result["total_cases"],
        raw_findings_count=result["raw_findings_count"],
        filtered_findings_count=result["filtered_findings_count"],
        noise_reduction_pct=result["noise_reduction_pct"],
        fp_precision=result["fp_precision"],
        fp_recall=result["fp_recall"],
        fix_validation_rate=result["fix_validation_rate"],
        details=result
    )
    db.add(run_record)
    await db.commit()
    await db.refresh(run_record)

    return run_record

@router.get("/latest", response_model=BenchmarkRunResponse)
async def get_latest_benchmark(db: AsyncSession = Depends(get_db)):
    stmt = select(BenchmarkRun).order_by(desc(BenchmarkRun.created_at))
    latest = (await db.execute(stmt)).scalars().first()

    if not latest:
        # Automatically run baseline benchmark if no runs exist yet
        result = await BenchmarkSuiteRunner.run_benchmark(suite_name="owasp_top10_corpus")
        latest = BenchmarkRun(
            name=result["name"],
            test_suite=result["test_suite"],
            total_cases=result["total_cases"],
            raw_findings_count=result["raw_findings_count"],
            filtered_findings_count=result["filtered_findings_count"],
            noise_reduction_pct=result["noise_reduction_pct"],
            fp_precision=result["fp_precision"],
            fp_recall=result["fp_recall"],
            fix_validation_rate=result["fix_validation_rate"],
            details=result
        )
        db.add(latest)
        await db.commit()
        await db.refresh(latest)

    return latest

@router.get("/history", response_model=List[BenchmarkRunResponse])
async def get_benchmark_history(db: AsyncSession = Depends(get_db)):
    stmt = select(BenchmarkRun).order_by(desc(BenchmarkRun.created_at)).limit(20)
    runs = (await db.execute(stmt)).scalars().all()
    return runs
