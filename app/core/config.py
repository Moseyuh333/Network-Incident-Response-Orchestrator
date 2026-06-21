"""Application configuration via pydantic-settings."""

from __future__ import annotations

from pydantic import field_validator
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
    llm_provider: str = "google"
    llm_api_key: str = ""
    google_api_key: str = ""
    llm_api_base: str = ""
    llm_model: str = ""
    llm_max_tokens: int = 1024
    llm_temperature: float = 0.1
    llm_model_anthropic: str = "claude-sonnet-4-20250514"
    llm_model_openai: str = "gpt-4o"
    llm_model_ollama: str = "llama3.1:8b"
    llm_model_gemini: str = "models/gemma-4-31b-it"
    llm_model_google: str = "models/gemma-4-31b-it"

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
    ml_anomaly_enabled: bool = True
    ml_anomaly_threshold: float = 0.92
    correlation_window_hours: int = 24
    correlation_max_evidence_items: int = 100

    # Listeners (disabled by default)
    enable_tcp_listener: bool = False
    enable_udp_listener: bool = False
    tcp_listener_port: int = 9001
    udp_listener_port: int = 9002
    listener_host: str = "127.0.0.1"

    # Response
    enable_real_response: bool = False
    allowed_real_actions: str = "simulate_block_ip,simulate_quarantine_host,simulate_disable_user,simulate_notify_admin"

    # CORS
    cors_origins: str = "*"

    @field_validator("debug", mode="before")
    @classmethod
    def parse_debug(cls, value: object) -> bool:
        """Accept common deployment strings from host environments."""
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"release", "prod", "production", "false", "0", "no", "off"}:
                return False
            if normalized in {"debug", "dev", "development", "true", "1", "yes", "on"}:
                return True
        return bool(value)

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
            "google": self.llm_model_google,
        }
        return mapping.get(self.llm_provider, self.llm_model_google)

    @property
    def allowed_actions_set(self) -> set[str]:
        return {a.strip() for a in self.allowed_real_actions.split(",") if a.strip()}


settings = Settings()
