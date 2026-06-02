"""LLM-related schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class LLMProviderConfig(BaseModel):
    """Configuration for an LLM provider."""

    provider: str = Field(..., pattern="^(anthropic|openai|ollama|gemini)$")
    api_key: str = ""
    api_base: str = ""
    model: str = ""
    max_tokens: int = 1024
    temperature: float = Field(default=0.1, ge=0.0, le=2.0)


class LLMHealthResponse(BaseModel):
    """Health check response for the LLM subsystem."""

    configured: bool
    provider: str
    model: str
    available: bool
