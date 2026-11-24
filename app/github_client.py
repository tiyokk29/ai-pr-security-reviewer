import hmac
import hashlib
from pathlib import PurePosixPath

import httpx

IGNORED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".lock", ".min.js", ".map",
}
IGNORED_FILENAMES = {
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "poetry.lock", "pipfile.lock", "gemfile.lock",
}


class GitHubAPIError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def verify_signature(payload: bytes, signature: str | None, secret: str) -> bool:
    if not secret or not signature or not signature.startswith("sha256="):
        return False
    supplied = signature.removeprefix("sha256=")
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, supplied)


def is_reviewable_file(filename: str) -> bool:
    normalized = filename.lower().replace("\\", "/")
    basename = PurePosixPath(normalized).name
    if basename in IGNORED_FILENAMES:
        return False
    return not any(normalized.endswith(extension) for extension in IGNORED_EXTENSIONS)


def filter_diff(files: list[dict]) -> list[dict]:
    filtered: list[dict] = []
    for item in files:
        filename = str(item.get("filename", ""))
        patch = item.get("patch")
        if filename and patch and is_reviewable_file(filename):
            filtered.append({
                "filename": filename,
                "status": item.get("status", "modified"),
                "patch": patch,
            })
    return filtered


class GitHubClient:
    def __init__(self, token: str) -> None:
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def get_pull_files(self, repository: str, pr_number: int) -> list[dict]:
        if not self.token:
            raise GitHubAPIError("GITHUB_TOKEN is not configured")
        url = f"https://api.github.com/repos/{repository}/pulls/{pr_number}/files"
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.get(url, headers=self.headers)
                response.raise_for_status()
                return response.json()
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            response_detail = exc.response.text[:500].replace("\n", " ")
            if status_code == 403:
                message = "GitHub API rate limit or forbidden"
            elif status_code == 404:
                message = "GitHub API 404: repository, PR, or token access unavailable"
            else:
                message = f"GitHub API returned HTTP {status_code}"
            raise GitHubAPIError(f"{message}: {response_detail}", status_code) from exc
        except httpx.RequestError as exc:
            raise GitHubAPIError(
                f"GitHub API request failed: {type(exc).__name__}: {exc}",
                None,
            ) from exc

    async def post_pr_comment(
        self,
        repository: str,
        pr_number: int,
        markdown: str,
    ) -> None:
        if not self.token:
            raise GitHubAPIError("GITHUB_TOKEN is not configured")
        url = f"https://api.github.com/repos/{repository}/issues/{pr_number}/comments"
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.post(
                    url,
                    headers=self.headers,
                    json={"body": markdown},
                )
                response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            response_detail = exc.response.text[:500].replace("\n", " ")
            raise GitHubAPIError(
                f"GitHub comment API returned HTTP {status_code}: {response_detail}",
                status_code,
            ) from exc
        except httpx.RequestError as exc:
            raise GitHubAPIError(
                f"GitHub comment request failed: {type(exc).__name__}: {exc}",
                None,
            ) from exc
