import hashlib
import hmac
import json

from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, create_engine

import app.main as main_module
from app.github_client import filter_diff, is_reviewable_file, verify_signature
from app.models import AuditOutput


def test_verify_signature_accepts_valid_payload():
    payload = b'{"action":"opened"}'
    secret = "test-secret"
    signature = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    assert verify_signature(payload, signature, secret)


def test_verify_signature_rejects_invalid_payload():
    payload = b'{"action":"opened"}'
    signature = "sha256=" + ("0" * 64)
    assert not verify_signature(payload, signature, "test-secret")
    assert not verify_signature(payload, None, "test-secret")


def test_filter_diff_ignores_non_code_files():
    files = [
        {"filename": "src/app.py", "patch": "+print('hello')", "status": "modified"},
        {"filename": "package-lock.json", "patch": "+dependency", "status": "modified"},
        {"filename": "assets/logo.png", "patch": "binary", "status": "added"},
        {"filename": "README.md", "patch": "+docs", "status": "modified"},
    ]
    assert not is_reviewable_file("package-lock.json")
    assert not is_reviewable_file("assets/logo.png")
    assert filter_diff(files) == [
        {"filename": "src/app.py", "status": "modified", "patch": "+print('hello')"},
        {"filename": "README.md", "status": "modified", "patch": "+docs"},
    ]


def test_webhook_rejects_invalid_signature(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(main_module, "engine", engine)
    client = TestClient(main_module.app)

    response = client.post(
        "/webhook/github",
        content=b'{"action":"opened"}',
        headers={"X-GitHub-Event": "pull_request", "X-Hub-Signature-256": "sha256=bad"},
    )
    assert response.status_code == 401


def test_webhook_ignores_unsupported_event(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(main_module, "engine", engine)
    monkeypatch.setattr(main_module.settings, "github_webhook_secret", "test-secret")
    client = TestClient(main_module.app)
    payload = b'{"action":"opened"}'
    signature = "sha256=" + hmac.new(
        b"test-secret", payload, hashlib.sha256
    ).hexdigest()

    response = client.post(
        "/webhook/github",
        content=payload,
        headers={
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": signature,
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] == "ignored"


def test_internal_error_response_does_not_disclose_exception(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    monkeypatch.setattr(main_module, "engine", engine)
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(main_module.settings, "github_webhook_secret", "test-secret")

    class FakeGitHubClient:
        def __init__(self, token):
            self.token = token

        async def get_pull_files(self, repository, pr_number):
            return [{
                "filename": "demo_vuln.py",
                "patch": "+API_KEY = 'demo'",
                "status": "added",
            }]

        async def post_pr_comment(self, repository, pr_number, markdown):
            pass

    class FailingSecurityAnalyzer:
        def __init__(self, api_key, model):
            pass

        def analyze(self, filtered_files):
            return AuditOutput(
                risk_level="SAFE",
                security_score=100,
                summary="No findings.",
                findings=[],
            )

    def failing_save_scan(payload, audit):
        raise RuntimeError("sensitive database implementation detail")

    monkeypatch.setattr(main_module, "GitHubClient", FakeGitHubClient)
    monkeypatch.setattr(main_module, "SecurityAnalyzer", FailingSecurityAnalyzer)
    monkeypatch.setattr(main_module, "save_scan", failing_save_scan)

    payload = json.dumps({
        "action": "opened",
        "number": 2,
        "repository": {"full_name": "tiyokk29/ai-pr-security-reviewer"},
        "pull_request": {
            "title": "Internal error test",
            "html_url": "https://example.invalid/pull/2",
            "head": {"sha": "test"},
        },
    }).encode()
    signature = "sha256=" + hmac.new(
        b"test-secret",
        payload,
        hashlib.sha256,
    ).hexdigest()

    response = TestClient(main_module.app).post(
        "/webhook/github",
        content=payload,
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": signature,
        },
    )

    assert response.status_code == 500
    assert response.json()["detail"] == (
        "An internal server error occurred while processing the pull request."
    )
    assert "sensitive database implementation detail" not in response.text
