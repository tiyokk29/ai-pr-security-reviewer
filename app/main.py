import json
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from sqlmodel import SQLModel, Session, create_engine, select

from app.analyzer import AnalysisError, SecurityAnalyzer
from app.config import get_settings
from app.github_client import GitHubAPIError, GitHubClient, filter_diff, verify_signature
from app.models import Finding, FindingOutput, Scan, ScanResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
settings = get_settings()

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)


@asynccontextmanager
async def lifespan(_: FastAPI):
    SQLModel.metadata.create_all(engine)
    yield


app = FastAPI(
    title="AI Code & Security PR Reviewer",
    version="1.0.0",
    lifespan=lifespan,
)


def save_scan(payload: dict[str, Any], audit: Any) -> Scan:
    repository = payload["repository"]["full_name"]
    pr = payload["pull_request"]
    with Session(engine) as session:
        scan = Scan(
            repository=repository,
            pr_number=int(payload["number"]),
            pr_title=str(pr.get("title", "")),
            pr_url=str(pr.get("html_url", "")),
            head_sha=str(pr.get("head", {}).get("sha", "")),
            risk_level=audit.risk_level.value,
            security_score=audit.security_score,
            summary=audit.summary,
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        if scan.id is None:
            raise RuntimeError("Failed to assign scan id")
        for finding in audit.findings:
            session.add(Finding(
                scan_id=scan.id,
                file=finding.file,
                line=finding.line,
                severity=finding.severity.value,
                category=finding.category,
                issue=finding.issue,
                recommendation=finding.recommendation,
            ))
        session.commit()
        session.refresh(scan)
        return scan


def render_markdown(scan: Scan, audit: Any) -> str:
    lines = [
        "## AI Security Review",
        "",
        f"**Risk:** `{scan.risk_level}`",
        f"**Security score:** `{scan.security_score}/100`",
        "",
        scan.summary,
        "",
    ]
    if audit.findings:
        lines.append("| Severity | Category | File | Issue | Recommendation |")
        lines.append("|---|---|---|---|---|")
        for finding in audit.findings:
            file_ref = finding.file if finding.line <= 1 else f"{finding.file}:{finding.line}"
            issue = finding.issue.replace("|", "\\|").replace("\n", " ")
            recommendation = finding.recommendation.replace("|", "\\|").replace("\n", " ")
            lines.append(
                f"| {finding.severity.value} | {finding.category} | "
                f"`{file_ref}` | {issue} | {recommendation} |"
            )
    else:
        lines.append("_No actionable security findings were detected._")
    return "\n".join(lines)


@app.post("/webhook/github")
async def github_webhook(request: Request) -> dict[str, str]:
    raw_body = await request.body()
    signature = request.headers.get("x-hub-signature-256")
    if not verify_signature(raw_body, signature, settings.github_webhook_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    payload = json.loads(raw_body)
    event = request.headers.get("x-github-event")
    if event != "pull_request":
        return {"status": "ignored", "reason": "event is not pull_request"}

    action = payload.get("action")
    if action not in {"opened", "synchronize"}:
        return {"status": "ignored", "reason": "unsupported pull_request action"}

    repository = payload["repository"]["full_name"]
    pr_number = int(payload["number"])
    github = GitHubClient(settings.github_token)
    try:
        raw_files = await github.get_pull_files(repository, pr_number)
    except GitHubAPIError as exc:
        logger.exception(
            "GitHub fetch failed (status=%s): %s",
            exc.status_code,
            exc,
        )
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    filtered_files = filter_diff(raw_files)
    try:
        analyzer = SecurityAnalyzer(settings.gemini_api_key, settings.gemini_model)
        audit = analyzer.analyze(filtered_files)
    except AnalysisError as exc:
        logger.exception("Gemini analysis failed: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    try:
        scan = save_scan(payload, audit)
        await github.post_pr_comment(
            repository,
            pr_number,
            render_markdown(scan, audit),
        )
    except GitHubAPIError as exc:
        logger.exception(
            "GitHub comment failed (status=%s): %s",
            exc.status_code,
            exc,
        )
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception(
            "Failed to persist scan or post GitHub comment: %s: %s",
            type(exc).__name__,
            exc,
        )
        raise HTTPException(
            status_code=500,
            detail="An internal server error occurred while processing the pull request.",
        ) from exc

    return {"status": "processed", "scan_id": str(scan.id)}


@app.get("/api/scans", response_model=list[ScanResponse])
def list_scans() -> list[ScanResponse]:
    with Session(engine) as session:
        scans = session.exec(
            select(Scan).order_by(Scan.created_at.desc())
        ).all()
        response: list[ScanResponse] = []
        for scan in scans:
            if scan.id is None:
                continue
            findings = session.exec(
                select(Finding).where(Finding.scan_id == scan.id)
            ).all()
            response.append(ScanResponse(
                id=scan.id,
                repository=scan.repository,
                pr_number=scan.pr_number,
                pr_title=scan.pr_title,
                pr_url=scan.pr_url,
                head_sha=scan.head_sha,
                risk_level=scan.risk_level,
                security_score=scan.security_score,
                summary=scan.summary,
                created_at=scan.created_at,
                findings=[
                    FindingOutput(
                        file=finding.file,
                        line=finding.line,
                        severity=finding.severity,
                        category=finding.category,
                        issue=finding.issue,
                        recommendation=finding.recommendation,
                    )
                    for finding in findings
                ],
            ))
        return response
