import hashlib
import hmac
import json

from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, create_engine

import app.main as main_module
from app.github_client import filter_diff, is_reviewable_file, verify_signature
from app.models import AuditOutput, FindingOutput


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


def test_critical_demo_payload_is_processed_without_502(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    monkeypatch.setattr(main_module, "engine", engine)
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(main_module.settings, "github_webhook_secret", "test-secret")
    monkeypatch.setattr(main_module.settings, "gemini_api_key", "test-key")

    class FakeGitHubClient:
        def __init__(self, token):
            self.token = token

        async def get_pull_files(self, repository, pr_number):
            return [{
                "filename": "demo_vuln.py",
                "status": "added",
                "patch": (
                    "+API_KEY = 'sk_live_demo_not_a_real_key'\n"
                    "+query = f\\\"SELECT * FROM users WHERE username = '{username}'\\\"\n"
                    "+os.system('ping ' + user_input)"
                ),
            }]

        async def post_pr_comment(self, repository, pr_number, markdown):
            assert "CRITICAL" in markdown

    class FakeSecurityAnalyzer:
        def __init__(self, api_key, model):
            pass

        def analyze(self, filtered_files):
            assert filtered_files[0]["filename"] == "demo_vuln.py"
            return AuditOutput(
                risk_level="CRITICAL",
                security_score=15,
                summary="Hardcoded secret, SQL injection, and command injection detected.",
                findings=[
                    FindingOutput(
                        file="demo_vuln.py",
                        line=4,
                        severity="CRITICAL",
                        category="Hardcoded Secret",
                        issue="API key is embedded in source.",
                        recommendation="Use environment variables or a secret manager.",
                    ),
                    FindingOutput(
                        file="demo_vuln.py",
                        line=8,
                        severity="CRITICAL",
                        category="SQL Injection",
                        issue="Username is inserted directly into SQL.",
                        recommendation="Use a parameterized query.",
                    ),
                    FindingOutput(
                        file="demo_vuln.py",
                        line=12,
                        severity="CRITICAL",
                        category="Command Injection",
                        issue="User input is passed to an OS shell.",
                        recommendation="Avoid shell execution and use argument lists.",
                    ),
                ],
            )

    monkeypatch.setattr(main_module, "GitHubClient", FakeGitHubClient)
    monkeypatch.setattr(main_module, "SecurityAnalyzer", FakeSecurityAnalyzer)

    payload = json.dumps({
        "action": "synchronize",
        "number": 2,
        "repository": {"full_name": "tiyokk29/ai-pr-security-reviewer"},
        "pull_request": {
            "title": "Clean vulnerability demo",
            "html_url": "https://github.com/tiyokk29/ai-pr-security-reviewer/pull/2",
            "head": {"sha": "2ed68e1"},
        },
    }).encode()
    signature = "sha256=" + hmac.new(
        b"test-secret",
        payload,
        hashlib.sha256,
    ).hexdigest()

    client = TestClient(main_module.app)
    response = client.post(
        "/webhook/github",
        content=payload,
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": signature,
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "processed"
