"""
Async test runner: executes all generated test cases against the live API
using httpx with controlled concurrency. Updates DB in real time.
"""

import asyncio
import copy
import json
import re
import time
from datetime import datetime
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import TestRun, TestCase, TestResult
from app.security_tests.generator import GeneratedTestCase
from app.security_tests.payloads import analyze_response
from app.core.config import settings


SEMAPHORE_LIMIT = settings.MAX_CONCURRENT_REQUESTS
REQUEST_TIMEOUT = settings.REQUEST_TIMEOUT_SECONDS


async def run_all_tests(
    db: AsyncSession,
    run_id: str,
    test_cases_data: list[GeneratedTestCase],
    base_url: str,
    swagger_spec: dict | None = None,
) -> dict:
    """
    Executes all test cases concurrently (bounded by semaphore).
    Persists results to DB. Returns summary stats.
    """
    semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)

    # Update run status to running
    run = await db.get(TestRun, run_id)
    run.status = "running"
    run.started_at = datetime.utcnow()
    run.total_cases = len(test_cases_data)
    await db.flush()

    # Persist all test case skeletons first
    db_cases: list[TestCase] = []
    for tc_data in test_cases_data:
        tc = TestCase(
            run_id=run_id,
            endpoint_path=tc_data.endpoint_path,
            http_method=tc_data.http_method,
            owasp_category=tc_data.owasp_category,
            attack_type=tc_data.attack_type,
            payload_used=tc_data.payload_used[:4000] if tc_data.payload_used else "",
            target_parameter=tc_data.target_parameter or "",
            severity=tc_data.severity,
        )
        db.add(tc)
        db_cases.append(tc)
    await db.flush()

    start_time = time.monotonic()

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(REQUEST_TIMEOUT),
        follow_redirects=True,
        verify=False,  # Security testing often targets internal/staging APIs
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
    ) as client:
        runtime_context = await _bootstrap_runtime_context(client, base_url, swagger_spec)
        tasks = [
            _execute_single(client, semaphore, db, tc_data, db_case, runtime_context)
            for tc_data, db_case in zip(test_cases_data, db_cases)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    duration = time.monotonic() - start_time

    # Tally results
    passed = sum(1 for r in results if isinstance(r, str) and r == "PASS")
    failed = sum(1 for r in results if isinstance(r, str) and r == "FAIL")
    errors = sum(1 for r in results if isinstance(r, str) and r == "ERROR" or isinstance(r, Exception))

    # Final run update
    run = await db.get(TestRun, run_id)
    run.status = "completed"
    run.completed_at = datetime.utcnow()
    run.passed = passed
    run.failed = failed
    run.errors = errors
    run.duration_seconds = round(duration, 2)
    await db.flush()

    return {
        "run_id": run_id,
        "total": len(test_cases_data),
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "duration_seconds": round(duration, 2),
    }


async def _execute_single(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    db: AsyncSession,
    tc_data: GeneratedTestCase,
    db_case: TestCase,
    runtime_context: dict[str, Any],
) -> str:
    """Execute one test case and persist its result."""
    async with semaphore:
        start = time.monotonic()
        status_code = None
        response_body = ""
        response_headers = {}
        error_detail = None

        try:
            request_kwargs = _build_request_kwargs(tc_data, runtime_context)
            auth_header = request_kwargs.get("headers", {}).get("Authorization", "")
            token_used = ""
            if isinstance(auth_header, str) and auth_header.startswith("Bearer "):
                token_used = auth_header.replace("Bearer ", "", 1)
            if not token_used:
                token_used = runtime_context.get("auth_token", "")
            db_case.payload_used = json.dumps(
                {
                    "mode": tc_data.execution_mode,
                    "url": request_kwargs["url"],
                    "method": request_kwargs["method"],
                    "headers": request_kwargs.get("headers", {}),
                    "params": request_kwargs.get("params", {}),
                    "json": request_kwargs.get("json"),
                    "data": request_kwargs.get("data"),
                    "session": {
                        "email": runtime_context.get("email", ""),
                        "register_endpoint": runtime_context.get("register_endpoint", ""),
                        "login_endpoint": runtime_context.get("login_endpoint", ""),
                        "token_used": token_used,
                    },
                },
                default=str,
            )[:12000]

            response = await client.request(**request_kwargs)
            status_code = response.status_code
            response_body = response.text[:5000]  # cap at 5KB
            response_headers = dict(response.headers)
            _capture_runtime_artifacts(runtime_context, request_kwargs["url"], response_body)

        except httpx.TimeoutException:
            error_detail = "Request timed out"
            status_code = 0
        except httpx.ConnectError as e:
            error_detail = f"Connection error: {str(e)}"
            status_code = 0
        except Exception as e:
            error_detail = f"Unexpected error: {str(e)}"
            status_code = 0

        elapsed_ms = (time.monotonic() - start) * 1000

        if error_detail:
            result_status = "ERROR"
            vuln_detail = error_detail
            recommendation = "Ensure the target API is accessible from the testing server."
        else:
            result_status, vuln_detail, recommendation = analyze_response(
                _payload_stub(db_case),
                status_code,
                response_body,
                response_headers,
            )

        tr = TestResult(
            case_id=db_case.id,
            result_status=result_status,
            http_status_code=status_code,
            response_body=response_body[:3000],
            response_headers=response_headers,
            response_time_ms=round(elapsed_ms, 2),
            vulnerability_detail=vuln_detail,
            recommendation=recommendation,
            executed_at=datetime.utcnow(),
        )
        db.add(tr)
        await db.flush()
        return result_status


def _build_request_kwargs(tc_data: GeneratedTestCase, runtime_context: dict[str, Any]) -> dict[str, Any]:
    headers = _resolve_placeholders(copy.deepcopy(tc_data.headers or {}), runtime_context)
    params = _resolve_placeholders(copy.deepcopy(tc_data.query_params or {}), runtime_context)
    body = _resolve_placeholders(copy.deepcopy(tc_data.body), runtime_context)
    resolved_url = _resolve_placeholders(tc_data.url, runtime_context)

    if tc_data.execution_mode == "stateful" and tc_data.attack_type not in {
        "jwt_none_alg", "jwt_weak_secret", "jwt_expired", "empty_bearer", "null_auth", "no_auth_header"
    }:
        token = runtime_context.get("auth_token")
        if token and "authorization" not in {k.lower() for k in headers.keys()}:
            headers["Authorization"] = f"Bearer {token}"

    request_kwargs = {
        "method": tc_data.http_method,
        "url": resolved_url,
        "headers": headers,
        "params": params,
    }
    if body is not None:
        if tc_data.content_type == "application/json":
            request_kwargs["json"] = body
        else:
            request_kwargs["data"] = body
    return request_kwargs


async def _bootstrap_runtime_context(client: httpx.AsyncClient, base_url: str, swagger_spec: dict | None = None) -> dict[str, Any]:
    context: dict[str, Any] = {
        "auth_token": "",
        "id": "101",
        "order_id": "101",
        "item_id": "101",
        "token": "",
        "login_endpoint": "",
        "register_endpoint": "",
    }
    unique_suffix = str(int(time.time()))
    email = f"hemanth_test{unique_suffix}@example.com"
    password = "Test@12345"
    context["email"] = email
    context["password"] = password

    register_candidates, login_candidates = _discover_auth_candidates(swagger_spec)
    context["register_endpoint"] = await _attempt_register(client, base_url, email, password, register_candidates)
    token, login_endpoint = await _attempt_login(client, base_url, email, password, login_candidates)
    context["login_endpoint"] = login_endpoint
    if token:
        context["auth_token"] = token
        context["token"] = token
    return context


async def _attempt_register(
    client: httpx.AsyncClient,
    base_url: str,
    email: str,
    password: str,
    discovered_candidates: list[tuple[str, str]],
) -> str:
    defaults = [
        ("POST", "/register"), ("POST", "/auth/register"), ("POST", "/api/register"),
        ("POST", "/users/register"), ("POST", "/signup"), ("POST", "/signup/admin"),
        ("POST", "/api/auth/register"), ("PUT", "/register"), ("PUT", "/signup"),
    ]
    candidates = _merge_candidates(discovered_candidates, defaults)
    payloads = [
        {"email": email, "password": password, "username": email.split("@")[0]},
        {"email": email, "password": password, "confirmPassword": password},
        {"username": email.split("@")[0], "password": password, "email": email},
    ]
    for method, path in candidates:
        for body in payloads:
            try:
                resp = await client.request(method, f"{base_url.rstrip('/')}{path}", json=body)
                if resp.status_code in (200, 201, 202, 409):
                    return path
            except Exception:
                continue
    return ""


async def _attempt_login(
    client: httpx.AsyncClient,
    base_url: str,
    email: str,
    password: str,
    discovered_candidates: list[tuple[str, str]],
) -> tuple[str, str]:
    defaults = [
        ("POST", "/login"), ("POST", "/auth/login"), ("POST", "/api/login"),
        ("POST", "/users/login"), ("POST", "/api/auth/login"), ("POST", "/signin"),
        ("POST", "/signin/admin"), ("POST", "/auth/signin"), ("PUT", "/login"),
    ]
    candidates = _merge_candidates(discovered_candidates, defaults)
    payloads = [
        {"email": email, "password": password, "username": email},
        {"username": email.split("@")[0], "password": password},
        {"email": email, "password": password},
    ]
    for method, path in candidates:
        for body in payloads:
            try:
                resp = await client.request(method, f"{base_url.rstrip('/')}{path}", json=body)
                token = _extract_token_from_response(resp)
                if token:
                    return token, path
            except Exception:
                continue
    return "", ""


def _extract_token_from_dict(data: Any) -> str:
    if isinstance(data, dict):
        for key in ("token", "access_token", "jwt", "id_token"):
            val = data.get(key)
            if isinstance(val, str) and val.strip():
                return val
        for value in data.values():
            found = _extract_token_from_dict(value)
            if found:
                return found
    if isinstance(data, list):
        for value in data:
            found = _extract_token_from_dict(value)
            if found:
                return found
    return ""


def _extract_token_from_response(resp: httpx.Response) -> str:
    auth_h = resp.headers.get("authorization", "") or resp.headers.get("Authorization", "")
    if isinstance(auth_h, str) and auth_h.startswith("Bearer "):
        return auth_h.replace("Bearer ", "", 1)
    if resp.status_code not in (200, 201, 202):
        return ""
    content_type = resp.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            return _extract_token_from_dict(resp.json())
        except Exception:
            return ""
    return ""


def _discover_auth_candidates(swagger_spec: dict | None) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    if not isinstance(swagger_spec, dict):
        return [], []
    paths = swagger_spec.get("paths", {}) or {}
    register_keys = ("register", "signup", "sign-up", "create-user", "createaccount")
    login_keys = ("login", "signin", "sign-in", "token", "authenticate", "auth")
    register: list[tuple[str, str]] = []
    login: list[tuple[str, str]] = []
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        p = str(path).lower()
        for method in ("get", "post", "put", "patch"):
            if method not in path_item:
                continue
            entry = (method.upper(), str(path))
            if any(k in p for k in register_keys):
                register.append(entry)
            if any(k in p for k in login_keys):
                login.append(entry)
    return register, login


def _merge_candidates(primary: list[tuple[str, str]], defaults: list[tuple[str, str]]) -> list[tuple[str, str]]:
    merged: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for method, path in primary + defaults:
        key = (method.upper(), path)
        if key in seen:
            continue
        seen.add(key)
        merged.append(key)
    return merged


def _capture_runtime_artifacts(runtime_context: dict[str, Any], url: str, response_body: str) -> None:
    if not response_body:
        return
    token_match = re.search(r'"(?:token|access_token|jwt|id_token)"\s*:\s*"([^"]+)"', response_body)
    if token_match:
        runtime_context["auth_token"] = token_match.group(1)
        runtime_context["token"] = token_match.group(1)
        if not runtime_context.get("login_endpoint"):
            runtime_context["login_endpoint"] = _path_from_url(url)

    id_match = re.search(r'"(?:id|order_id|item_id|user_id)"\s*:\s*"?([A-Za-z0-9-]+)"?', response_body)
    if id_match:
        value = id_match.group(1)
        runtime_context["id"] = value
        runtime_context["order_id"] = value
        runtime_context["item_id"] = value

    segs = [s for s in url.split("/") if s]
    if segs and segs[-1].isdigit():
        runtime_context["id"] = segs[-1]


def _path_from_url(url: str) -> str:
    try:
        parts = url.split("://", 1)
        remainder = parts[1] if len(parts) == 2 else parts[0]
        slash_idx = remainder.find("/")
        return remainder[slash_idx:] if slash_idx >= 0 else "/"
    except Exception:
        return ""


def _resolve_placeholders(obj: Any, runtime_context: dict[str, Any]) -> Any:
    if obj is None:
        return None
    if isinstance(obj, str):
        out = obj
        for key, value in runtime_context.items():
            out = out.replace(f"{{{{{key}}}}}", str(value))
        return out
    if isinstance(obj, dict):
        return {k: _resolve_placeholders(v, runtime_context) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve_placeholders(v, runtime_context) for v in obj]
    return obj


def _payload_stub(tc: TestCase):
    """Minimal stub so analyze_response can match by owasp_category/attack_type."""
    from app.security_tests.payloads import TestPayload
    return TestPayload(
        attack_type=tc.attack_type,
        owasp_category=tc.owasp_category,
        severity=tc.severity,
        payload=tc.payload_used,
        description="",
        inject_in="",
    )