"""Provider adapters for LLM-assisted incident analysis."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from app.core.config import Settings, settings
from app.core.redaction import redact_secrets


@dataclass(frozen=True)
class LLMResult:
    """Normalized result from an LLM provider."""

    available: bool
    provider: str
    model: str
    text: str = ""
    fallback_reason: str | None = None


class GoogleGenAIProvider:
    """Google Gen AI provider using the official google-genai SDK."""

    provider_name = "google-genai"

    def __init__(self, config: Settings = settings) -> None:
        self.config = config
        self.api_key = config.llm_api_key or config.google_api_key
        self.model = config.effective_llm_model

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def generate(self, prompt: str) -> LLMResult:
        """Generate a raw text response, returning a redacted error on failure."""
        if not self.is_configured:
            return LLMResult(
                available=False,
                provider=self.provider_name,
                model=self.model,
                fallback_reason="LLM API key is not configured",
            )

        try:
            from google import genai
        except ImportError as exc:
            return LLMResult(
                available=False,
                provider=self.provider_name,
                model=self.model,
                fallback_reason=redact_secrets(exc, [self.api_key]),
            )

        client = genai.Client(api_key=self.api_key)
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                response = client.models.generate_content(
                    model=self.model,
                    contents=prompt,
                    config={
                        "temperature": self.config.llm_temperature,
                        "max_output_tokens": self.config.llm_max_tokens,
                    },
                )
                return LLMResult(
                    available=True,
                    provider=self.provider_name,
                    model=self.model,
                    text=response.text or "",
                )
            except Exception as exc:  # pragma: no cover
                last_error = exc
                message = str(exc)
                if attempt < 2 and ("503" in message or "UNAVAILABLE" in message):
                    time.sleep(4 * (attempt + 1))
                    continue
                break
        if last_error is not None:
            return LLMResult(
                available=False,
                provider=self.provider_name,
                model=self.model,
                fallback_reason=redact_secrets(last_error, [self.api_key]),
            )
        return LLMResult(
            available=False,
            provider=self.provider_name,
            model=self.model,
            fallback_reason="LLM provider returned no response",
        )

    def generate_json(
        self,
        prompt: str,
        response_schema: dict[str, Any],
    ) -> LLMResult:
        """Generate a JSON response, returning a redacted error on failure."""
        if not self.is_configured:
            return LLMResult(
                available=False,
                provider=self.provider_name,
                model=self.model,
                fallback_reason="LLM API key is not configured",
            )

        try:
            from google import genai
        except ImportError as exc:
            return LLMResult(
                available=False,
                provider=self.provider_name,
                model=self.model,
                fallback_reason=redact_secrets(exc, [self.api_key]),
            )

        client = genai.Client(api_key=self.api_key)
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                response = client.models.generate_content(
                    model=self.model,
                    contents=prompt,
                    config={
                        "temperature": self.config.llm_temperature,
                        "max_output_tokens": self.config.llm_max_tokens,
                        "response_mime_type": "application/json",
                        "response_json_schema": response_schema,
                    },
                )
                return LLMResult(
                    available=True,
                    provider=self.provider_name,
                    model=self.model,
                    text=response.text or "",
                )
            except Exception as exc:  # pragma: no cover - provider failures vary by SDK/API
                last_error = exc
                message = str(exc)
                if attempt < 2 and ("503" in message or "UNAVAILABLE" in message):
                    time.sleep(4 * (attempt + 1))
                    continue
                break
        if last_error is not None:
            return LLMResult(
                available=False,
                provider=self.provider_name,
                model=self.model,
                fallback_reason=redact_secrets(last_error, [self.api_key]),
            )
        return LLMResult(
            available=False,
            provider=self.provider_name,
            model=self.model,
            fallback_reason="LLM provider returned no response",
        )
