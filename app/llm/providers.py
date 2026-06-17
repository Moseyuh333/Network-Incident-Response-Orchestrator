"""Provider adapters for LLM-assisted incident analysis.

Two providers are supported:
- ``GoogleGenAIProvider``: the official Google Gen AI SDK (default).
- ``TokenRouterProvider``: an OpenAI-compatible HTTP client targeting
  ``https://api.tokenrouter.com/v1``. Works with any model name the
  TokenRouter account has access to (e.g. ``MiniMax-M3``).

Select via ``LLM_PROVIDER`` in ``.env``:
    LLM_PROVIDER=google          # default
    LLM_PROVIDER=tokenrouter
    LLM_MODEL=gemini-2.5-flash-lite
    LLM_MODEL=MiniMax-M3
"""

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


# ── TokenRouter (OpenAI-compatible) provider ──────────────────────────


class TokenRouterProvider:
    """LLM provider for the TokenRouter OpenAI-compatible endpoint.

    TokenRouter exposes a standard OpenAI ``/v1/chat/completions``
    API. We talk to it directly with ``httpx`` (no extra SDK) so the
    project stays dependency-light. The same resilient-retry + 30s
    deadline used by the Google provider is reused here so the rest of
    the system has one consistent failure mode.

    Configure via ``.env``:

        LLM_PROVIDER=tokenrouter
        LLM_API_BASE=https://api.tokenrouter.com/v1
        LLM_API_KEY=sk-...                 # required
        LLM_MODEL=MiniMax-M3              # or any model your account has
    """

    provider_name = "tokenrouter"

    def __init__(self, config: Settings = settings) -> None:
        self.config = config
        self.api_key = config.llm_api_key
        # Allow the base URL to be overridden in .env; default to the
        # TokenRouter public endpoint.
        self.api_base = (config.llm_api_base or "https://api.tokenrouter.com/v1").rstrip("/")
        self.model = config.effective_llm_model
        # Same resilience tunables as the Google provider so the two
        # adapters behave the same under load / quota exhaustion.
        self._max_attempts: int = 3
        self._total_timeout_seconds: float = 30.0
        self._initial_backoff_seconds: float = 1.0
        self._max_backoff_seconds: float = 4.0

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def generate(self, prompt: str) -> LLMResult:
        return self._call(use_json=False, prompt=prompt, response_schema=None)

    def generate_json(
        self,
        prompt: str,
        response_schema: dict[str, Any],
    ) -> LLMResult:
        return self._call(
            use_json=True,
            prompt=prompt,
            response_schema=response_schema,
        )

    def _call(
        self,
        *,
        use_json: bool,
        prompt: str,
        response_schema: dict[str, Any] | None,
    ) -> LLMResult:
        if not self.is_configured:
            return LLMResult(
                available=False,
                provider=self.provider_name,
                model=self.model,
                fallback_reason="LLM API key is not configured",
            )
        return self._call_with_resilience(
            use_json=use_json,
            prompt=prompt,
            response_schema=response_schema,
        )

    @staticmethod
    def _strip_think_blocks(text: str) -> str:
        """Strip noise from the model output before JSON parsing.

        Reasoning-tuned models on TokenRouter (e.g. ``MiniMax-M3``)
        wrap their final answer in two kinds of noise:

        - ```` blocks (chain-of-thought)
        - ```` ```json ... ``` ```` markdown fences around the JSON

        Pydantic's JSON parser fails on the leading character in
        both cases. We strip both wrappers and return the remainder.
        """
        import re

        # 1. Drop ````...```` blocks (non-greedy, multiline).
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)

        # 2. Drop a leading ```` ```json ```` or ```` ``` ```` markdown
        #    fence and its matching closer. The model emits these even
        #    though we did not request ``response_format: json_object``.
        text = re.sub(
            r"^\s*```(?:json)?\s*\n?(.*?)\n?\s*```\s*$",
            r"\1",
            text,
            flags=re.DOTALL,
        )
        # 3. If only the opener is present (no close), drop everything
        #    before the first ```` line.
        if "```" in text and not text.lstrip().startswith("{"):
            parts = text.split("```", 2)
            text = parts[-1] if len(parts) >= 3 else text
        return text.strip()

    def _call_with_resilience(
        self,
        *,
        use_json: bool,
        prompt: str,
        response_schema: dict[str, Any] | None,
    ) -> LLMResult:
        """Bounded-retry HTTP call to the OpenAI-compatible endpoint.

        Mirrors the Google provider's resilience: 3 attempts, exponential
        backoff capped at 4s, 30s total deadline, 503/UNAVAILABLE fails
        immediately (no point retrying an overloaded model).
        """
        try:
            import httpx
        except ImportError as exc:
            return LLMResult(
                available=False,
                provider=self.provider_name,
                model=self.model,
                fallback_reason=redact_secrets(exc, [self.api_key]),
            )

        url = f"{self.api_base}/chat/completions"
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a defensive security analyst."},
                {"role": "user", "content": prompt},
            ],
            "temperature": self.config.llm_temperature,
            "max_tokens": self.config.llm_max_tokens,
        }
        # NOTE: we intentionally do NOT send ``response_format: json_object``
        # to TokenRouter. The reasoning-tuned models we route through it
        # (e.g. ``MiniMax-M3``) start every response with a ```` block;
        # when the OpenAI strict-JSON mode is enabled, the model gets
        # cut off mid-thought and never reaches the actual JSON. Without
        # that flag the model emits `````` then the JSON object on
        # a single line, which our ``_strip_think_blocks`` helper cleans
        # up before JSON parsing.
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        deadline = time.monotonic() + self._total_timeout_seconds
        backoff = self._initial_backoff_seconds
        last_error: Exception | None = None
        attempts = 0

        while attempts < self._max_attempts and time.monotonic() < deadline:
            attempts += 1
            try:
                response = httpx.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=max(1.0, deadline - time.monotonic()),
                )
                # 503 / UNAVAILABLE: fail fast, the upstream is overloaded.
                if response.status_code == 503 or "UNAVAILABLE" in response.text:
                    return LLMResult(
                        available=False,
                        provider=self.provider_name,
                        model=self.model,
                        fallback_reason=redact_secrets(
                            f"503 UNAVAILABLE: {response.text[:200]}",
                            [self.api_key],
                        ),
                    )
                if response.status_code >= 400:
                    return LLMResult(
                        available=False,
                        provider=self.provider_name,
                        model=self.model,
                        fallback_reason=redact_secrets(
                            f"HTTP {response.status_code}: {response.text[:200]}",
                            [self.api_key],
                        ),
                    )
                data = response.json()
                # OpenAI response shape: choices[0].message.content
                text = (
                    data.get("choices", [{}])[0]
                    .get("message", {})
                    .get("content", "")
                ) or ""
                # Some models (notably reasoning-tuned ones served via
                # TokenRouter) wrap their final answer in <think>...</think>
                # blocks even when asked for JSON. The first JSON object
                # is almost always after the closing tag, so we strip
                # the block and re-parse.
                text = self._strip_think_blocks(text)
                if not text.strip():
                    return LLMResult(
                        available=False,
                        provider=self.provider_name,
                        model=self.model,
                        fallback_reason="LLM returned empty content",
                    )
                return LLMResult(
                    available=True,
                    provider=self.provider_name,
                    model=self.model,
                    text=text,
                )
            except Exception as exc:  # network, JSON parse, etc.
                last_error = exc
                if attempts >= self._max_attempts or time.monotonic() >= deadline:
                    break
                time.sleep(min(backoff, max(0.0, deadline - time.monotonic())))
                backoff = min(backoff * 2, self._max_backoff_seconds)

        return LLMResult(
            available=False,
            provider=self.provider_name,
            model=self.model,
            fallback_reason=redact_secrets(
                str(last_error) if last_error else "TokenRouter request failed",
                [self.api_key],
            ),
        )


# ── Provider factory ─────────────────────────────────────────────────


def get_provider(config: Settings | None = None):
    """Return the configured LLM provider based on ``LLM_PROVIDER``.

    Falls back to GoogleGenAIProvider if the configured provider is
    unknown, so existing deployments keep working.
    """
    cfg = config or settings
    name = (cfg.llm_provider or "google").strip().lower()
    if name in ("tokenrouter", "openai", "openai-compatible"):
        return TokenRouterProvider(cfg)
    return GoogleGenAIProvider(cfg)
