"""Unit tests for the LLM provider layer (Google + TokenRouter).

The TokenRouter path is exercised against a mocked httpx so the
tests do not consume API quota. The factory and config wiring is
also covered.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch


from app.core.config import Settings
from app.llm.providers import (
    GoogleGenAIProvider,
    TokenRouterProvider,
    get_provider,
)


def test_google_provider_requires_key() -> None:
    """Without LLM_API_KEY, the provider must report unconfigured and
    return a fallback_reason instead of raising.
    """
    cfg = Settings(llm_api_key="", google_api_key="", _env_file=None)
    p = GoogleGenAIProvider(cfg)
    assert p.is_configured is False
    r = p.generate("hello")
    assert r.available is False
    assert "not configured" in (r.fallback_reason or "")


def test_tokenrouter_provider_requires_key() -> None:
    """The same empty-key contract must hold for the TokenRouter
    adapter so the rest of the system has one consistent failure
    mode.
    """
    cfg = Settings(llm_api_key="", _env_file=None)
    p = TokenRouterProvider(cfg)
    assert p.is_configured is False
    r = p.generate("hello")
    assert r.available is False
    assert "not configured" in (r.fallback_reason or "")


def test_tokenrouter_provider_default_base_url() -> None:
    """When LLM_API_BASE is unset, the provider must default to the
    public TokenRouter endpoint.
    """
    cfg = Settings(llm_api_key="sk-test", _env_file=None)
    p = TokenRouterProvider(cfg)
    assert p.api_base == "https://api.tokenrouter.com/v1"
    assert p.is_configured is True


def test_tokenrouter_provider_custom_base_url() -> None:
    """LLM_API_BASE should be honored (trailing slash stripped)."""
    cfg = Settings(
        llm_api_key="sk-test",
        llm_api_base="https://router.example.com/v1/",
        _env_file=None,
    )
    p = TokenRouterProvider(cfg)
    assert p.api_base == "https://router.example.com/v1"


def test_factory_picks_tokenrouter_when_configured() -> None:
    cfg = Settings(llm_provider="tokenrouter", llm_api_key="sk-test", _env_file=None)
    p = get_provider(cfg)
    assert isinstance(p, TokenRouterProvider)


def test_factory_picks_google_when_configured() -> None:
    cfg = Settings(llm_provider="google", llm_api_key="sk-test", _env_file=None)
    p = get_provider(cfg)
    assert isinstance(p, GoogleGenAIProvider)


def test_factory_falls_back_to_google_for_unknown_provider() -> None:
    cfg = Settings(llm_provider="mystery", llm_api_key="sk-test", _env_file=None)
    p = get_provider(cfg)
    assert isinstance(p, GoogleGenAIProvider)


def test_tokenrouter_provider_text_completion_ok(monkeypatch) -> None:
    """A successful 200 with a 'choices' array returns text."""
    fake_response = SimpleNamespace(
        status_code=200,
        text=json.dumps({
            "choices": [{"message": {"content": "Hello back"}}],
        }),
        json=lambda: {
            "choices": [{"message": {"content": "Hello back"}}],
        },
    )
    fake_post = lambda *a, **kw: fake_response  # noqa: E731
    with patch("httpx.post", fake_post):
        cfg = Settings(llm_api_key="sk-test", _env_file=None)
        p = TokenRouterProvider(cfg)
        r = p.generate("hello")
    assert r.available is True
    assert r.text == "Hello back"
    assert r.provider == "tokenrouter"


def test_tokenrouter_provider_empty_content_is_unavailable() -> None:
    """Empty content from the upstream should NOT be reported as
    available — the consumer needs to know to fall back.
    """
    fake_response = SimpleNamespace(
        status_code=200,
        text=json.dumps({"choices": [{"message": {"content": ""}}]}),
        json=lambda: {"choices": [{"message": {"content": ""}}]},
    )
    with patch("httpx.post", lambda *a, **kw: fake_response):
        cfg = Settings(llm_api_key="sk-test", _env_file=None)
        p = TokenRouterProvider(cfg)
        r = p.generate("hello")
    assert r.available is False
    assert "empty" in (r.fallback_reason or "")


def test_tokenrouter_provider_503_fails_fast() -> None:
    """A 503 must be surfaced immediately (no retries — upstream
    overloaded).
    """
    fake_response = SimpleNamespace(
        status_code=503,
        text="UNAVAILABLE: high demand",
    )
    with patch("httpx.post", lambda *a, **kw: fake_response):
        cfg = Settings(llm_api_key="sk-test", _env_file=None)
        p = TokenRouterProvider(cfg)
        r = p.generate("hello")
    assert r.available is False
    assert "503" in (r.fallback_reason or "")


def test_tokenrouter_provider_401_redacts_key() -> None:
    """An auth error must not leak the raw API key in the response."""
    fake_response = SimpleNamespace(
        status_code=401,
        text="UNAUTHORIZED sk-leaked-secret-key",
    )
    with patch("httpx.post", lambda *a, **kw: fake_response):
        cfg = Settings(llm_api_key="sk-leaked-secret-key", _env_file=None)
        p = TokenRouterProvider(cfg)
        r = p.generate("hello")
    assert r.available is False
    assert "sk-leaked-secret-key" not in (r.fallback_reason or ""), (
        "raw API key must not appear in the fallback_reason"
    )
    assert "[REDACTED]" in (r.fallback_reason or "")


def test_tokenrouter_provider_no_response_format(monkeypatch) -> None:
    """By design, the TokenRouter provider does NOT send
    ``response_format: json_object``. Reasoning-tuned models served
    via TokenRouter (e.g. ``MiniMax-M3``) start every response with
    a ```` block; when the OpenAI strict-JSON mode is enabled
    the model is cut off mid-thought and never reaches the actual
    JSON. The provider therefore relies on free-form text output
    and the ``_strip_think_blocks`` helper to clean the response.
    """
    captured: dict = {}
    fake_response = SimpleNamespace(
        status_code=200,
        text=json.dumps({"choices": [{"message": {"content": "{}"}}]}),
        json=lambda: {"choices": [{"message": {"content": "{}"}}]},
    )

    def fake_post(url, json=None, **kwargs):
        captured["payload"] = json
        return fake_response

    with patch("httpx.post", fake_post):
        cfg = Settings(llm_api_key="sk-test", _env_file=None)
        p = TokenRouterProvider(cfg)
        p.generate_json("hello", {"type": "object"})

    payload = captured["payload"]
    assert "response_format" not in payload, (
        "TokenRouter should not send response_format — see comment"
    )


def test_tokenrouter_provider_passes_model_name() -> None:
    """The configured model name must reach the upstream request."""
    captured: dict = {}
    fake_response = SimpleNamespace(
        status_code=200,
        text=json.dumps({"choices": [{"message": {"content": "ok"}}]}),
    )

    def fake_post(url, json=None, **kwargs):
        captured["payload"] = json
        return fake_response

    with patch("httpx.post", fake_post):
        cfg = Settings(llm_api_key="sk-test", llm_model="MiniMax-M3", _env_file=None)
        p = TokenRouterProvider(cfg)
        p.generate("hi")

    assert captured["payload"]["model"] == "MiniMax-M3"
