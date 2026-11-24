import json
import logging
import time

from google import genai
from google.genai import types

from app.models import AuditOutput

logger = logging.getLogger(__name__)


class AnalysisError(RuntimeError):
    pass


def format_diff(files: list[dict]) -> str:
    sections = []
    for item in files:
        sections.append(
            f"File: {item['filename']} ({item['status']})\n```diff\n{item['patch']}\n```"
        )
    return "\n\n".join(sections)


class SecurityAnalyzer:
    def __init__(self, api_key: str, model: str) -> None:
        if not api_key:
            raise AnalysisError("GEMINI_API_KEY is not configured")
        self.client = genai.Client(api_key=api_key)
        self.model = model

    def analyze(self, filtered_files: list[dict]) -> AuditOutput:
        if not filtered_files:
            return AuditOutput(
                risk_level="SAFE",
                security_score=100,
                summary="No reviewable code changes were found.",
                findings=[],
            )

        prompt = (
            "Act as an application security reviewer. Inspect only the supplied "
            "GitHub pull request diff. Detect hardcoded secrets/API keys, SQL "
            "and command injection, XSS, insecure cryptography, broken "
            "authentication or authorization, and security-relevant logic bugs. "
            "Return no findings when evidence is insufficient. Use exact file "
            "names and line numbers from added diff lines when possible.\n\n"
            f"{format_diff(filtered_files)}"
        )
        models = list(dict.fromkeys([
            self.model,
            "gemini-3.5-flash",
            "gemini-3.1-flash-lite",
        ]))
        last_error: Exception | None = None
        for model in models:
            for attempt in range(3):
                try:
                    response = self.client.models.generate_content(
                        model=model,
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            response_mime_type="application/json",
                            response_schema=AuditOutput,
                            temperature=0.1,
                        ),
                    )
                    if not response.text:
                        raise AnalysisError("Gemini returned an empty response")
                    return self._parse_response(response.text)
                except AnalysisError:
                    raise
                except Exception as exc:
                    last_error = exc
                    status_code = getattr(exc, "code", None)
                    if status_code is None:
                        status_code = getattr(exc, "status_code", None)
                    if str(status_code) in {"429", "503"} and attempt < 2:
                        delay = 2 ** attempt
                        logger.warning(
                            "Gemini %s on %s; retrying in %s seconds (attempt %s/3)",
                            status_code,
                            model,
                            delay,
                            attempt + 1,
                        )
                        time.sleep(delay)
                        continue
                    logger.exception(
                        "Gemini API call failed on model %s: %s",
                        model,
                        exc,
                    )
                    break

        detail = str(last_error).replace("\n", " ").strip() if last_error else "unknown error"
        if len(detail) > 500:
            detail = detail[:497] + "..."
        logger.error("Gemini analysis failed: %s", detail)
        raise AnalysisError(f"Gemini analysis failed: {detail}") from last_error

    @staticmethod
    def _parse_response(text: str) -> AuditOutput:
        cleaned = text.strip()
        if cleaned.startswith("```"):
            lines = cleaned.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            cleaned = "\n".join(lines).strip()
        try:
            data = json.loads(cleaned)
            return AuditOutput.model_validate(data)
        except Exception as exc:
            logger.exception("Gemini returned invalid JSON")
            raise AnalysisError(
                f"Gemini returned invalid structured JSON: {type(exc).__name__}: {exc}"
            ) from exc
