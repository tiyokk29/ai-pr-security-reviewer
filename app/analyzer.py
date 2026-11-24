import logging

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
        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=AuditOutput,
                    temperature=0.1,
                ),
            )
            if not response.text:
                raise AnalysisError("Gemini returned an empty response")
            return AuditOutput.model_validate_json(response.text)
        except AnalysisError:
            raise
        except Exception as exc:
            logger.exception("Gemini analysis failed")
            status_code = getattr(exc, "code", None)
            message = str(exc).replace("\n", " ").strip()
            if len(message) > 300:
                message = message[:297] + "..."
            if status_code:
                raise AnalysisError(
                    f"Gemini API returned {status_code}: {message}"
                ) from exc
            raise AnalysisError(f"Gemini analysis failed: {message}") from exc
