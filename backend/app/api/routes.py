from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from pydantic import BaseModel
import json
import logging

from app.db.database import get_db
from app.models.models import TestRun, TestCase
from app.schemas.schemas import (
    TestRunOut,
    TestCaseWithResult,
    TestResultDetail,
    RunResultsResponse,
    GenerateTestCasesResponse,
    GeneratedCaseOut,
)
from app.services.analytics import compute_analytics
from app.security_tests.generator import generate_test_cases
from app.security_tests.runner import run_all_tests

router = APIRouter()
logger = logging.getLogger(__name__)


class ScanRequest(BaseModel):
    swagger_spec: dict
    base_url: str


# Health check for API router
@router.get("/")
async def api_root():
    return {"message": "API router working"}


# Generate test cases
@router.post("/generate", response_model=GenerateTestCasesResponse)
async def generate(body: ScanRequest):
    try:
        cases = generate_test_cases(body.swagger_spec, body.base_url)
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to parse spec: {str(e)}"
        )

    if not cases:
        raise HTTPException(
            status_code=400,
            detail="No endpoints found in the Swagger spec."
        )

    return GenerateTestCasesResponse(
        total=len(cases),
        cases=[
            GeneratedCaseOut(
                endpoint_path=c.endpoint_path,
                http_method=c.http_method,
                owasp_category=c.owasp_category,
                attack_type=c.attack_type,
                payload_used=(c.payload_used or "")[:200],
                target_parameter=c.target_parameter or "",
                severity=c.severity,
            )
            for c in cases
        ],
    )


# Run security tests
@router.post("/run")
async def run_tests(body: ScanRequest, db: AsyncSession = Depends(get_db)):
    try:
        cases = generate_test_cases(body.swagger_spec, body.base_url)
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to parse spec: {str(e)}"
        )

    if not cases:
        raise HTTPException(
            status_code=400,
            detail="No endpoints found in the Swagger spec."
        )

    try:
        run = TestRun(project_id="anonymous", status="pending")

        db.add(run)
        await db.flush()

        await run_all_tests(db, run.id, cases, body.base_url, body.swagger_spec)

        await db.commit()
        await db.refresh(run)

        return JSONResponse(
            status_code=200,
            content={
                "id": str(run.id),
                "status": run.status,
                "message": "Security scan completed"
            },
        )

    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Run failed: {str(e)}"
        )


# Get results
@router.get("/runs/{run_id}/results", response_model=RunResultsResponse)
async def get_results(run_id: str, db: AsyncSession = Depends(get_db)):
    try:
        run_res = await db.execute(
            select(TestRun).where(TestRun.id == run_id)
        )
        run = run_res.scalar_one_or_none()

        if not run:
            raise HTTPException(
                status_code=404,
                detail="Run not found"
            )

        cases_res = await db.execute(
            select(TestCase)
            .where(TestCase.run_id == run_id)
            .options(selectinload(TestCase.result))
            .order_by(TestCase.owasp_category, TestCase.severity)
        )

        cases = cases_res.scalars().all()
        analytics = await compute_analytics(db, run_id)
        session = _extract_stateful_session(cases)

        # Large payloads can make this response slow/heavy for big scans.
        # Keep enough context for payload inspection while avoiding oversized JSON.
        result_rows = []
        for case in cases:
            payload = case.payload_used or ""
            if len(payload) > 8000:
                payload = payload[:8000]
            result_rows.append(
                TestCaseWithResult(
                    id=str(case.id),
                    endpoint_path=case.endpoint_path,
                    http_method=case.http_method,
                    owasp_category=case.owasp_category,
                    attack_type=case.attack_type,
                    payload_used=payload,
                    target_parameter=case.target_parameter,
                    severity=case.severity,
                    result=(
                        TestResultDetail.model_validate(case.result)
                        if case.result is not None else None
                    ),
                )
            )

        return RunResultsResponse(
            run=TestRunOut.model_validate(run),
            results=result_rows,
            analytics=analytics,
            session=session,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to build run results for run_id=%s", run_id)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to build run results: {str(e)}"
        )


def _extract_stateful_session(cases: list[TestCase]) -> dict:
    best = None
    for case in cases:
        if not case.payload_used:
            continue
        try:
            payload = json.loads(case.payload_used)
        except Exception:
            continue
        if payload.get("mode") != "stateful":
            continue
        session = payload.get("session", {}) if isinstance(payload.get("session"), dict) else {}
        token = session.get("token_used", "")
        if not token:
            headers = payload.get("headers", {}) if isinstance(payload.get("headers"), dict) else {}
            auth = headers.get("Authorization", "") or headers.get("authorization", "")
            if isinstance(auth, str) and auth.startswith("Bearer "):
                token = auth.replace("Bearer ", "", 1)
        candidate = {
            "email": session.get("email", ""),
            "register_endpoint": session.get("register_endpoint", ""),
            "login_endpoint": session.get("login_endpoint", ""),
            "token": token,
            "token_masked": _mask_token(token),
        }
        if candidate["token"]:
            return candidate
        if not best:
            best = candidate
    if best:
        return best
    return {
        "email": "",
        "register_endpoint": "",
        "login_endpoint": "",
        "token": "",
        "token_masked": "",
    }


def _mask_token(token: str) -> str:
    if not token:
        return ""
    if len(token) <= 16:
        return token
    return f"{token[:12]}...{token[-8:]}"
    