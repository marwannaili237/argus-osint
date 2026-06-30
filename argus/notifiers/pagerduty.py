"""PagerDuty Events API v2 notifier."""
import logging
import aiohttp
from argus.config import settings
from argus.notifiers.base import BaseNotifier

logger = logging.getLogger(__name__)
PD_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"


class PagerDutyNotifier(BaseNotifier):
    name = "pagerduty"

    def __init__(self):
        self.enabled = bool(settings.PAGERDUTY_API_KEY)
        self.api_key = settings.PAGERDUTY_API_KEY or ""

    async def send(self, title: str, message: str, severity: str = "info", **kwargs) -> bool:
        if not self.enabled:
            return False
        action = kwargs.get("action", "trigger")
        pd_severity = {"critical": "critical", "high": "error", "medium": "warning", "low": "info"}.get(severity, "info")
        payload = {
            "routing_key": self.api_key,
            "event_action": action,
            "payload": {"summary": f"{title}: {message}", "severity": pd_severity, "source": "argus-osint", "component": kwargs.get("component", "scanner")},
            "dedup_key": kwargs.get("dedup_key", title.replace(" ", "_").lower()[:100]),
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(PD_EVENTS_URL, json=payload) as resp:
                    return resp.status == 202
        except Exception as e:
            logger.error(f"PagerDuty send failed: {e}")
            return False

    async def test_connection(self) -> bool:
        return await self.send("Test", "Argus OSINT test", "info", action="trigger")
