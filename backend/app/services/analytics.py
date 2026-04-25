from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.models.models import TestRun, TestCase, TestResult


async def compute_analytics(db: AsyncSession, run_id: str) -> dict:
    """Compute full analytics for a test run."""
    result = await db.execute(
        select(TestCase)
        .where(TestCase.run_id == run_id)
        .options(selectinload(TestCase.result))
    )
    cases = result.scalars().all()

    total = len(cases)
    passed = failed = errors = 0
    by_category: dict[str, dict] = {}
    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    top_vulns: list[dict] = []

    for case in cases:
        r = case.result
        if not r:
            errors += 1
            continue

        if r.result_status == "PASS":
            passed += 1
        elif r.result_status == "FAIL":
            failed += 1
        else:
            errors += 1

        # By OWASP category
        cat = case.owasp_category
        if cat not in by_category:
            by_category[cat] = {"total": 0, "passed": 0, "failed": 0, "errors": 0}
        by_category[cat]["total"] += 1
        if r.result_status == "PASS":
            by_category[cat]["passed"] += 1
        elif r.result_status == "FAIL":
            by_category[cat]["failed"] += 1
        else:
            by_category[cat]["errors"] += 1

        # By severity (only for failures)
        if r.result_status == "FAIL":
            sev = case.severity.lower()
            if sev in by_severity:
                by_severity[sev] += 1

            # Track top vulnerabilities
            if r.vulnerability_detail:
                top_vulns.append({
                    "attack_type": case.attack_type,
                    "endpoint": f"{case.http_method} {case.endpoint_path}",
                    "severity": case.severity,
                    "detail": r.vulnerability_detail[:200],
                    "recommendation": r.recommendation or "",
                })

    # Limit top vulns
    top_vulns_sorted = sorted(
        top_vulns,
        key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"], 4)
    )[:20]

    pass_rate = round((passed / total * 100) if total > 0 else 0, 1)

    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "pass_rate": pass_rate,
        "by_category": by_category,
        "by_severity": by_severity,
        "top_vulnerabilities": top_vulns_sorted,
    }