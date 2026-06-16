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
        # Bounded retry/timeout tunables. Tuned to keep the incident pipeline
        # responsive even when the upstream model is degraded.
        self._max_attempts: int = 3
        self._total_timeout_seconds: float = 30.0
        self._initial_backoff_seconds: float = 1.0
        self._max_backoff_seconds: float = 4.0

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def _call_with_resilience(
        self,
        *,
        use_json: bool,
        prompt: str,
        response_schema: dict[str, Any] | None,
    ) -> LLMResult:
        """Call the GenAI SDK with bounded retries and a hard total timeout.

        Google GenAI returns ``503 UNAVAILABLE`` when a model is overloaded.
        Retrying the same overloaded model only burns time, so the first
        ``503/UNAVAILABLE`` response is surfaced immediately. Other transient
        errors (network glitches, ``ResourceExhausted``) get up to two retries
        with exponential backoff. The cumulative wall-clock budget defaults to
        30 seconds so a misconfigured or slow model can never wedge the
        incident-response pipeline.
        """
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
        config: dict[str, Any] = {
            "temperature": self.config.llm_temperature,
            "max_output_tokens": self.config.llm_max_tokens,
        }
        if use_json and response_schema is not None:
            config["response_mime_type"] = "application/json"
            config["response_json_schema"] = response_schema

        deadline = time.monotonic() + self._total_timeout_seconds
        backoff = self._initial_backoff_seconds
        last_error: Exception | None = None
        attempts = 0

        while attempts < self._max_attempts and time.monotonic() < deadline:
            attempts += 1
            try:
                response = client.models.generate_content(
                    model=self.model,
                    contents=prompt,
                    config=config,
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
                # ``503 UNAVAILABLE`` means the model itself is overloaded.
                # No amount of retrying will change that on a short timescale,
                # so surface the failure immediately instead of piling on
                # sleep + extra requests.
                if "503" in message or "UNAVAILABLE" in message:
                    break
                if attempts >= self._max_attempts or time.monotonic() >= deadline:
                    break
                time.sleep(min(backoff, max(0.0, deadline - time.monotonic())))
                backoff = min(backoff * 2, self._max_backoff_seconds)

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

    def generate(self, prompt: str) -> LLMResult:
        """Generate a raw text response, returning a redacted error on failure."""
        if not self.is_configured:
            return LLMResult(
                available=False,
                provider=self.provider_name,
                model=self.model,
                fallback_reason="LLM API key is not configured",
            )
        return self._call_with_resilience(use_json=False, prompt=prompt, response_schema=None)

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
        return self._call_with_resilience(
            use_json=True,
            prompt=prompt,
            response_schema=response_schema,
        )
