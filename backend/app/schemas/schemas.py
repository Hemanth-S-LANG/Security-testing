from pydantic import BaseModel, ConfigDict
from typing import Optional, Any
from datetime import datetime


# ── Test Generation ───────────────────────────────────────────
class GeneratedCaseOut(BaseModel):
    endpoint_path: str
    http_method: str
    owasp_category: str
    attack_type: str
    payload_used: str
    target_parameter: str
    severity: str


class GenerateTestCasesResponse(BaseModel):
    total: int
    cases: list[GeneratedCaseOut]


# ── Test Runs ─────────────────────────────────────────────────
class TestRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    project_id: Optional[str]
    status: str
    total_cases: int
    passed: int
    failed: int
    errors: int
    duration_seconds: Optional[float]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime


# ── Test Results ──────────────────────────────────────────────
class TestResultDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    result_status: str
    http_status_code: Optional[int]
    response_time_ms: Optional[float]
    vulnerability_detail: Optional[str]
    recommendation: Optional[str]
    executed_at: datetime


class TestCaseWithResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    endpoint_path: str
    http_method: str
    owasp_category: str
    attack_type: str
    payload_used: Optional[str]
    target_parameter: Optional[str]
    severity: str
    result: Optional[TestResultDetail] = None


class RunResultsResponse(BaseModel):
    run: TestRunOut
    results: list[TestCaseWithResult]
    analytics: dict
    session: Optional[dict[str, Any]] = None