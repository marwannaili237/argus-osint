"""
Argus OSINT Configuration

Centralized configuration management using Pydantic Settings.
All settings are loaded from environment variables with optional .env file fallback.
"""

from __future__ import annotations

from typing import Optional

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Database ──────────────────────────────────────────────────────
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///./argus.db",
        description="SQLAlchemy async database connection string",
    )

    # ── Bot ──────────────────────────────────────────────────────────
    BOT_TOKEN: Optional[str] = Field(default=None, description="Telegram bot token")
    BOT_WEBHOOK_URL: Optional[str] = Field(
        default=None, description="Telegram bot webhook URL"
    )

    # ── OSINT API Keys ───────────────────────────────────────────────
    SHODAN_API_KEY: Optional[str] = Field(
        default=None, description="Shodan API key"
    )
    VIRUSTOTAL_API_KEY: Optional[str] = Field(
        default=None, description="VirusTotal API key"
    )
    SECURITYTRAILS_API_KEY: Optional[str] = Field(
        default=None, description="SecurityTrails API key"
    )
    HUNTER_API_KEY: Optional[str] = Field(
        default=None, description="Hunter.io API key"
    )
    CLEARBIT_API_KEY: Optional[str] = Field(
        default=None, description="Clearbit API key"
    )
    FULLCONTACT_API_KEY: Optional[str] = Field(
        default=None, description="FullContact API key"
    )

    # ── Notification / Integration Webhooks ──────────────────────────
    SLACK_WEBHOOK_URL: Optional[str] = Field(
        default=None, description="Slack incoming webhook URL"
    )
    DISCORD_WEBHOOK_URL: Optional[str] = Field(
        default=None, description="Discord webhook URL"
    )
    MATTERMOST_WEBHOOK_URL: Optional[str] = Field(
        default=None, description="Mattermost webhook URL"
    )
    TEAMS_WEBHOOK_URL: Optional[str] = Field(
        default=None, description="Microsoft Teams webhook URL"
    )

    # ── External Service Integrations ─────────────────────────────────
    PAGERDUTY_API_KEY: Optional[str] = Field(
        default=None, description="PagerDuty API key"
    )
    JIRA_URL: Optional[str] = Field(
        default=None, description="Jira server base URL"
    )
    JIRA_TOKEN: Optional[str] = Field(
        default=None, description="Jira personal access token"
    )
    OPENCTI_URL: Optional[str] = Field(
        default=None, description="OpenCTI platform URL"
    )
    OPENCTI_TOKEN: Optional[str] = Field(
        default=None, description="OpenCTI API token"
    )
    ELASTICSEARCH_URL: Optional[str] = Field(
        default=None, description="Elasticsearch connection URL"
    )

    # ── TheHive ────────────────────────────────────────────────────────
    THEHIVE_URL: Optional[str] = Field(
        default=None, description="TheHive platform URL"
    )
    THEHIVE_API_KEY: Optional[str] = Field(
        default=None, description="TheHive API key"
    )

    # ── SMTP (Email) ──────────────────────────────────────────────────
    SMTP_HOST: Optional[str] = Field(
        default=None, description="SMTP server hostname"
    )
    SMTP_PORT: Optional[int] = Field(
        default=None, description="SMTP server port"
    )
    SMTP_USER: Optional[str] = Field(
        default=None, description="SMTP authentication username"
    )
    SMTP_PASSWORD: Optional[str] = Field(
        default=None, description="SMTP authentication password"
    )

    # ── Telegram ──────────────────────────────────────────────────────
    TELEGRAM_CHANNEL_ID: Optional[str] = Field(
        default=None, description="Default Telegram channel for notifications"
    )

    # ── Security ───────────────────────────────────────────────────────
    SECRET_KEY: str = Field(
        default="change-me-in-production-use-a-long-random-string",
        description="Secret key for JWT signing and TOTP generation",
    )
    ENCRYPTION_KEY: Optional[str] = Field(
        default=None,
        description="Fernet symmetric key for evidence encryption at rest",
    )

    # ── Network ───────────────────────────────────────────────────────
    IP_ALLOWLIST: Optional[str] = Field(
        default=None,
        description="Comma-separated list of allowed IP addresses (empty = allow all)",
    )
    CORS_ORIGINS: str = Field(
        default="*",
        description="Comma-separated list of allowed CORS origins",
    )

    # ── Application ───────────────────────────────────────────────────
    LOG_LEVEL: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )
    APP_ENV: str = Field(
        default="production",
        description="Application environment (production, staging, development)",
    )

    # ── Validators ────────────────────────────────────────────────────

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid:
            raise ValueError(f"LOG_LEVEL must be one of {valid}, got '{v}'")
        return upper

    @field_validator("APP_ENV")
    @classmethod
    def validate_app_env(cls, v: str) -> str:
        valid = {"production", "staging", "development"}
        if v.lower() not in valid:
            raise ValueError(f"APP_ENV must be one of {valid}, got '{v}'")
        return v.lower()

    @field_validator("CORS_ORIGINS")
    @classmethod
    def parse_cors_origins(cls, v: str) -> str:
        """Validate CORS origins format but keep as string for middleware use."""
        if v.strip() != "*":
            origins = [o.strip() for o in v.split(",") if o.strip()]
            for origin in origins:
                if not origin.startswith(("http://", "https://")):
                    raise ValueError(
                        f"Invalid CORS origin: '{origin}'. "
                        "Must start with http:// or https://, or use '*'"
                    )
        return v

    @field_validator("SMTP_PORT")
    @classmethod
    def validate_smtp_port(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and not (1 <= v <= 65535):
            raise ValueError(f"SMTP_PORT must be between 1 and 65535, got {v}")
        return v

    @field_validator("IP_ALLOWLIST")
    @classmethod
    def parse_ip_allowlist(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        import ipaddress

        ips = [ip.strip() for ip in v.split(",") if ip.strip()]
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
            except ValueError as exc:
                raise ValueError(f"Invalid IP address '{ip}': {exc}") from exc
        return v

    @model_validator(mode="after")
    def validate_smtp_group(self) -> "Settings":
        """If any SMTP field is set, ensure all required fields are present."""
        smtp_fields = {self.SMTP_HOST, self.SMTP_PORT, self.SMTP_USER, self.SMTP_PASSWORD}
        set_count = sum(1 for f in smtp_fields if f is not None)
        if 0 < set_count < 4:
            raise ValueError(
                "All SMTP fields must be set together: "
                "SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD"
            )
        return self

    # ── Convenience Properties ─────────────────────────────────────────

    @property
    def is_development(self) -> bool:
        return self.APP_ENV == "development"

    @property
    def cors_origin_list(self) -> list[str]:
        """Return CORS origins as a parsed list."""
        if self.CORS_ORIGINS.strip() == "*":
            return ["*"]
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def ip_allowlist_set(self) -> set[str] | None:
        """Return IP allowlist as a set, or None if not configured."""
        if self.IP_ALLOWLIST is None:
            return None
        return {ip.strip() for ip in self.IP_ALLOWLIST.split(",") if ip.strip()}


def get_settings() -> Settings:
    """Return a cached Settings singleton."""
    from functools import lru_cache

    @lru_cache(maxsize=1)
    def _cached() -> Settings:
        return Settings()

    return _cached()
