from __future__ import annotations

import sys
import types

from app.core.config import Settings
from app.llm.providers import GoogleGenAIProvider


def test_config_resolves_google_model_from_env_style_override() -> None:
    # ``_env_file=None`` disables .env loading but does NOT clear env
    # vars. We must explicitly reset ``llm_model`` so the property does
    # not short-circuit on a value inherited from the environment.
    config = Settings(
        llm_provider="google",
        llm_model="",
        llm_model_google="gemma-4-31b",
        _env_file=None,
    )

    assert config.effective_llm_model == "gemma-4-31b"


def test_provider_redacts_secret_from_sdk_errors(monkeypatch) -> None:
    secret = "test-secret-that-must-not-leak"

    class FakeClient:
        def __init__(self, api_key: str) -> None:
            self.api_key = api_key
            self.models = self

        def generate_content(self, **kwargs):
            raise RuntimeError(f"provider failed with api_key={secret}")

    fake_genai = types.SimpleNamespace(Client=FakeClient)
    fake_google = types.ModuleType("google")
    fake_google.genai = fake_genai
    monkeypatch.setitem(sys.modules, "google", fake_google)

    provider = GoogleGenAIProvider(
        Settings(
            llm_provider="google",
            llm_api_key=secret,
            llm_model="gemma-4-31b",
            _env_file=None,
        )
    )

    result = provider.generate_json("{}", {"type": "object"})

    assert result.available is False
    assert secret not in (result.fallback_reason or "")
    assert "[REDACTED]" in (result.fallback_reason or "")
