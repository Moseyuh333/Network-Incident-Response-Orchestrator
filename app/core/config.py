"""Application configuration via pydantic-settings."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # App
    app_name: str = "Network Incident Response Orchestrator"
    app_version: str = "0.1.0"
    debug: bool = False
    log_level: str = "INFO"

    # Database
    database_url: str = "sqlite:///./niro.db"

    # LLM
    llm_provider: str = "anthropic"
    llm_api_key: str = ""
    llm_api_base: str = ""
    llm_model: str = ""
    llm_max_tokens: int = 1024
    llm_temperature: float = 0.1
    llm_model_anthropic: str = "claude-sonnet-4-20250514"
    llm_model_openai: str = "gpt-4o"
    llm_model_ollama: str = "llama3.1:8b"
    llm_model_gemini: str = "gemini-1.5-flash"

    # Detection thresholds
    port_scan_threshold: int = 10
    port_scan_window_seconds: int = 60
    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 120
    web_attack_patterns: bool = True
    exfil_threshold_mb: int = 50
    exfil_window_seconds: int = 300
    beacon_interval_min: int = 5
    beacon_interval_max: int = 60
    beacon_repeat_count: int = 6
    flood_threshold: int = 100
    flood_window_seconds: int = 60

    # Response
    enable_real_response: bool = False
    allowed_real_actions: str = "simulate_block_ip,simulate_quarantine_host,simulate_disable_user,simulate_notify_admin"

    # CORS
    cors_origins: str = "*"

    @property
    def effective_llm_model(self) -> str:
        """Return the resolved model name for the active provider."""
        if self.llm_model:
            return self.llm_model
        mapping = {
            "anthropic": self.llm_model_anthropic,
            "openai": self.llm_model_openai,
            "ollama": self.llm_model_ollama,
            "gemini": self.llm_model_gemini,
        }
        return mapping.get(self.llm_provider, self.llm_model_anthropic)

    @property
    def allowed_actions_set(self) -> set[str]:
        return {a.strip() for a in self.allowed_real_actions.split(",") if a.strip()}


settings = Settings()
