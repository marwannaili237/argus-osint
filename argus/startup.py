"""
Argus OSINT – Startup Validation

Runs comprehensive checks against configuration values at application
startup.  Returns lists of warnings and errors for operator review.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from argus.config import get_settings
from argus.plugins import ALL_PLUGINS, refresh_all_plugins_list

logger = logging.getLogger(__name__)


@dataclass
class StartupCheckResult:
    """Result of a single startup check."""

    name: str
    status: str  # "ok", "warning", "error"
    message: str


@dataclass
class StartupReport:
    """Aggregate report of all startup checks."""

    checks: list[StartupCheckResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    elapsed: float = 0.0

    def add(self, name: str, status: str, message: str) -> None:
        self.checks.append(StartupCheckResult(name=name, status=status, message=message))
        if status == "error":
            self.errors.append(f"[{name}] {message}")
        elif status == "warning":
            self.warnings.append(f"[{name}] {message}")


# ── Checkers ─────────────────────────────────────────────────────────

def _check_database(report: StartupReport) -> None:
    """Verify database connectivity by performing a simple connection test."""
    import asyncio
    from argus.database import engine

    async def _test() -> str:
        try:
            async with engine.connect() as conn:
                from sqlalchemy import text
                await conn.execute(text("SELECT 1"))
            return "ok"
        except Exception as exc:
            return str(exc)

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    result = loop.run_until_complete(_test())
    if result == "ok":
        report.add("database", "ok", "Database connection successful")
    else:
        report.add("database", "error", f"Database connection failed: {result}")


def _check_bot_token(report: StartupReport) -> None:
    """Validate bot token format if configured."""
    settings = get_settings()
    if settings.BOT_TOKEN is None:
        report.add("bot_token", "ok", "No bot token configured (bot features disabled)")
        return

    # Telegram bot tokens are like: 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
    pattern = r"^\d{5,10}:[A-Za-z0-9_-]{30,}$"
    if re.match(pattern, settings.BOT_TOKEN):
        report.add("bot_token", "ok", "Bot token format is valid")
    else:
        report.add("bot_token", "warning", "Bot token does not match expected Telegram format")


def _check_api_key(report: StartupReport, name: str, key: str | None, expected_prefix: str, expected_length: int = 32) -> None:
    """Validate an API key format."""
    if key is None:
        report.add(name, "ok", f"{name} not configured (optional)")
        return

    if len(key) < expected_length:
        report.add(name, "warning", f"{name} appears too short (expected ≥{expected_length} chars)")
    elif expected_prefix and not key.startswith(expected_prefix):
        report.add(name, "warning", f"{name} does not start with expected prefix '{expected_prefix}'")
    else:
        report.add(name, "ok", f"{name} configured and format looks valid")


def _check_api_keys(report: StartupReport) -> None:
    """Validate all OSINT API key formats."""
    settings = get_settings()
    _check_api_key(report, "shodan_api_key", settings.SHODAN_API_KEY, "", 32)
    _check_api_key(report, "virustotal_api_key", settings.VIRUSTOTAL_API_KEY, "", 64)
    _check_api_key(report, "securitytrails_api_key", settings.SECURITYTRAILS_API_KEY, "", 32)
    _check_api_key(report, "hunter_api_key", settings.HUNTER_API_KEY, "", 32)
    _check_api_key(report, "clearbit_api_key", settings.CLEARBIT_API_KEY, "sk_", 20)
    _check_api_key(report, "fullcontact_api_key", settings.FULLCONTACT_API_KEY, "", 32)


def _check_smtp(report: StartupReport) -> None:
    """Check SMTP configuration if set."""
    settings = get_settings()
    if settings.SMTP_HOST is None:
        report.add("smtp", "ok", "SMTP not configured (email notifications disabled)")
        return

    if not (1 <= (settings.SMTP_PORT or 0) <= 65535):
        report.add("smtp", "error", "SMTP_PORT out of valid range 1-65535")
    else:
        report.add("smtp", "ok", f"SMTP configured: {settings.SMTP_HOST}:{settings.SMTP_PORT}")


def _check_url_format(report: StartupReport, name: str, url: str | None) -> None:
    """Validate a URL format."""
    if url is None:
        report.add(name, "ok", f"{name} not configured (optional)")
        return

    try:
        parsed = urlparse(url)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            report.add(name, "ok", f"{name} URL format is valid")
        else:
            report.add(name, "warning", f"{name} URL has invalid format")
    except Exception as exc:
        report.add(name, "error", f"{name} URL parse error: {exc}")


def _check_webhooks_and_integrations(report: StartupReport) -> None:
    """Validate webhook URLs and integration endpoints."""
    settings = get_settings()
    _check_url_format(report, "slack_webhook", settings.SLACK_WEBHOOK_URL)
    _check_url_format(report, "discord_webhook", settings.DISCORD_WEBHOOK_URL)
    _check_url_format(report, "mattermost_webhook", settings.MATTERMOST_WEBHOOK_URL)
    _check_url_format(report, "teams_webhook", settings.TEAMS_WEBHOOK_URL)
    _check_url_format(report, "jira_url", settings.JIRA_URL)
    _check_url_format(report, "opencti_url", settings.OPENCTI_URL)
    _check_url_format(report, "elasticsearch_url", settings.ELASTICSEARCH_URL)
    _check_url_format(report, "thehive_url", settings.THEHIVE_URL)

    if settings.PAGERDUTY_API_KEY is not None:
        _check_api_key(report, "pagerduty_api_key", settings.PAGERDUTY_API_KEY, "", 20)
    else:
        report.add("pagerduty_api_key", "ok", "PagerDuty not configured (optional)")

    if settings.OPENCTI_TOKEN is not None:
        _check_api_key(report, "opencti_token", settings.OPENCTI_TOKEN, "", 16)
    else:
        report.add("opencti_token", "ok", "OpenCTI token not configured (optional)")

    if settings.THEHIVE_API_KEY is not None:
        _check_api_key(report, "thehive_api_key", settings.THEHIVE_API_KEY, "", 16)
    else:
        report.add("thehive_api_key", "ok", "TheHive API key not configured (optional)")


def _check_secret_key(report: StartupReport) -> None:
    """Warn if the default secret key is still in use."""
    settings = get_settings()
    if settings.SECRET_KEY == "change-me-in-production-use-a-long-random-string":
        report.add(
            "secret_key",
            "warning",
            "Default SECRET_KEY is in use. Change this in production!",
        )
    else:
        report.add("secret_key", "ok", "SECRET_KEY is customized")


def _check_encryption_key(report: StartupReport) -> None:
    """Check Fernet encryption key format if configured."""
    settings = get_settings()
    if settings.ENCRYPTION_KEY is None:
        report.add("encryption_key", "warning", "No encryption key set – evidence encryption disabled")
        return

    try:
        from cryptography.fernet import Fernet
        Fernet(settings.ENCRYPTION_KEY.encode())
        report.add("encryption_key", "ok", "Fernet encryption key is valid")
    except Exception:
        report.add("encryption_key", "error", "Fernet encryption key is invalid")


def _check_plugin_count(report: StartupReport) -> None:
    """Log the number of registered plugins."""
    refresh_all_plugins_list()
    count = len(ALL_PLUGINS)
    report.add(
        "plugins",
        "ok" if count > 0 else "warning",
        f"{count} plugin(s) registered",
    )


def _check_ip_allowlist(report: StartupReport) -> None:
    """Validate IP allowlist configuration."""
    settings = get_settings()
    if settings.IP_ALLOWLIST is None:
        report.add("ip_allowlist", "ok", "No IP allowlist configured (all IPs allowed)")
    else:
        count = len(settings.ip_allowlist_set or set())
        report.add("ip_allowlist", "ok", f"{count} IP(s) in allowlist")


def _check_cors(report: StartupReport) -> None:
    """Validate CORS configuration."""
    settings = get_settings()
    origins = settings.cors_origin_list
    if "*" in origins:
        if settings.APP_ENV == "production":
            report.add("cors", "warning", "CORS allows all origins in production – consider restricting")
        else:
            report.add("cors", "ok", "CORS allows all origins (development mode)")
    else:
        report.add("cors", "ok", f"CORS allows {len(origins)} origin(s)")


# ── Main Entry Point ──────────────────────────────────────────────────

def run_startup_checks() -> StartupReport:
    """Execute all startup validation checks.

    Returns a StartupReport with detailed results for logging and alerting.
    """
    start = time.monotonic()
    report = StartupReport()

    logger.info("Running Argus OSINT startup checks …")

    _check_database(report)
    _check_bot_token(report)
    _check_api_keys(report)
    _check_smtp(report)
    _check_webhooks_and_integrations(report)
    _check_secret_key(report)
    _check_encryption_key(report)
    _check_plugin_count(report)
    _check_ip_allowlist(report)
    _check_cors(report)

    report.elapsed = round(time.monotonic() - start, 3)

    # Summary logging
    for check in report.checks:
        level = logging.INFO if check.status == "ok" else (
            logging.WARNING if check.status == "warning" else logging.ERROR
        )
        logger.log(level, "  [%s] %s – %s", check.status.upper(), check.name, check.message)

    if report.errors:
        logger.error("Startup checks completed with %d ERROR(S) and %d WARNING(S) in %.3fs",
                      len(report.errors), len(report.warnings), report.elapsed)
    else:
        logger.info("Startup checks completed with %d WARNING(S) in %.3fs",
                     len(report.warnings), report.elapsed)

    return report
