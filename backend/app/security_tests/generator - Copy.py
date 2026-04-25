"""
Generates security test cases by combining extracted endpoints
with OWASP payloads. Produces one TestCase per (endpoint, payload) pair.
"""

from app.security_tests.swagger_parser import Endpoint, parse_swagger, get_safe_body
from app.security_tests.payloads import (
    ALL_PAYLOADS, TestPayload,
    SQL_INJECTION_PAYLOADS, BROKEN_AUTH_PAYLOADS,
    BROKEN_ACCESS_PAYLOADS, SECURITY_MISCONFIG_PAYLOADS,
    INPUT_VALIDATION_PAYLOADS,
)
from dataclasses import dataclass, field
from typing import Any


@dataclass
class GeneratedTestCase:
    endpoint_path: str
    http_method: str
    owasp_category: str
    attack_type: str
    payload_used: str
    target_parameter: str
    severity: str
    # Runtime fields for execution
    url: str = ""
    headers: dict = field(default_factory=dict)
    query_params: dict = field(default_factory=dict)
    body: Any = None
    content_type: str = "application/json"


def generate_test_cases(
    swagger_spec: dict,
    base_url: str,
) -> list[GeneratedTestCase]:
    """
    Main entry point: parse spec → generate test cases.
    Returns a list of GeneratedTestCase objects ready for execution.
    """
    endpoints = parse_swagger(swagger_spec)
    test_cases: list[GeneratedTestCase] = []

    for endpoint in endpoints:
        test_cases.extend(_generate_for_endpoint(endpoint, base_url))

    # Add global misconfiguration checks (one-time, not per-endpoint)
    for mc_payload in SECURITY_MISCONFIG_PAYLOADS:
        test_cases.append(GeneratedTestCase(
            endpoint_path="/",
            http_method="GET",
            owasp_category=mc_payload.owasp_category,
            attack_type=mc_payload.attack_type,
            payload_used=str(mc_payload.payload or ""),
            target_parameter="global",
            severity=mc_payload.severity,
            url=base_url.rstrip("/") + "/",
            headers=_build_headers(mc_payload),
        ))

    return test_cases


def _generate_for_endpoint(
    endpoint: Endpoint, base_url: str
) -> list[GeneratedTestCase]:
    cases: list[GeneratedTestCase] = []
    url_base = base_url.rstrip("/") + endpoint.path

    # Get injectable params grouped by location
    query_params = [p for p in endpoint.params if p.location == "query"]
    body_params = [p for p in endpoint.params if p.location == "body"]
    path_params = [p for p in endpoint.params if p.location == "path"]

    # ── SQL + Input Validation → inject into query and body params ────
    for payload in SQL_INJECTION_PAYLOADS + INPUT_VALIDATION_PAYLOADS:
        if payload.inject_in == "query" and query_params:
            for param in query_params:
                if param.schema_type in ("string", "integer", "number"):
                    cases.append(GeneratedTestCase(
                        endpoint_path=endpoint.path,
                        http_method=endpoint.method,
                        owasp_category=payload.owasp_category,
                        attack_type=payload.attack_type,
                        payload_used=str(payload.payload),
                        target_parameter=param.name,
                        severity=payload.severity,
                        url=url_base,
                        query_params={param.name: str(payload.payload)},
                        content_type="application/json",
                    ))

        elif payload.inject_in == "body" and body_params and endpoint.method in ("POST", "PUT", "PATCH"):
            for param in body_params:
                if param.schema_type in ("string",):
                    safe_body = get_safe_body(endpoint)
                    safe_body[param.name] = payload.payload
                    cases.append(GeneratedTestCase(
                        endpoint_path=endpoint.path,
                        http_method=endpoint.method,
                        owasp_category=payload.owasp_category,
                        attack_type=payload.attack_type,
                        payload_used=str(payload.payload),
                        target_parameter=param.name,
                        severity=payload.severity,
                        url=url_base,
                        body=safe_body,
                        content_type="application/json",
                    ))

    # ── Broken Auth → inject into Authorization header ────────────────
    for payload in BROKEN_AUTH_PAYLOADS:
        if payload.inject_in == "header":
            headers = _build_headers(payload)
            cases.append(GeneratedTestCase(
                endpoint_path=endpoint.path,
                http_method=endpoint.method,
                owasp_category=payload.owasp_category,
                attack_type=payload.attack_type,
                payload_used=str(payload.payload),
                target_parameter="Authorization",
                severity=payload.severity,
                url=url_base,
                headers=headers,
            ))
        elif payload.inject_in == "body" and endpoint.method in ("POST", "PUT", "PATCH"):
            cases.append(GeneratedTestCase(
                endpoint_path=endpoint.path,
                http_method=endpoint.method,
                owasp_category=payload.owasp_category,
                attack_type=payload.attack_type,
                payload_used=str(payload.payload),
                target_parameter="request_body",
                severity=payload.severity,
                url=url_base,
                body=payload.payload,
                content_type="application/json",
            ))

    # ── Broken Access Control → inject into path params ──────────────
    for payload in BROKEN_ACCESS_PAYLOADS:
        if payload.inject_in == "path":
            # Replace path params with the malicious value
            injected_path = endpoint.path
            if path_params:
                for pp in path_params:
                    injected_path = injected_path.replace(f"{{{pp.name}}}", str(payload.payload))
            else:
                # Append to path if no params (probe extra segments)
                injected_path = endpoint.path.rstrip("/") + "/" + str(payload.payload)

            cases.append(GeneratedTestCase(
                endpoint_path=endpoint.path,
                http_method=endpoint.method,
                owasp_category=payload.owasp_category,
                attack_type=payload.attack_type,
                payload_used=str(payload.payload),
                target_parameter="path",
                severity=payload.severity,
                url=base_url.rstrip("/") + injected_path,
            ))
        elif payload.inject_in == "body" and endpoint.method in ("POST", "PUT", "PATCH"):
            safe_body = get_safe_body(endpoint)
            safe_body.update(payload.payload if isinstance(payload.payload, dict) else {})
            cases.append(GeneratedTestCase(
                endpoint_path=endpoint.path,
                http_method=endpoint.method,
                owasp_category=payload.owasp_category,
                attack_type=payload.attack_type,
                payload_used=str(payload.payload),
                target_parameter="request_body",
                severity=payload.severity,
                url=url_base,
                body=safe_body,
                content_type="application/json",
            ))

    return cases


def _build_headers(payload: TestPayload) -> dict:
    """Build request headers based on payload type."""
    if payload.attack_type in ("jwt_none_alg", "jwt_weak_secret", "jwt_expired", "empty_bearer", "null_auth"):
        return {"Authorization": f"Bearer {payload.payload}"}
    if payload.attack_type == "no_auth_header":
        return {}
    if payload.attack_type == "cors_wildcard":
        return {"Origin": str(payload.payload)}
    return {}