import hashlib
import hmac
import json
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient
from sqlmodel import SQLModel, create_engine

import app.main as main_module
from app.github_client import filter_diff, is_reviewable_file, verify_signature


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


def test_github_missing_repository_error_is_actionable():
    from app.github_client import GitHubAPIError

    error = GitHubAPIError(
        "GitHub API 404: repository or pull request is missing",
        404,
    )
    assert error.status_code == 404


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
