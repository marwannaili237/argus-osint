"""Slack webhook notifier."""
import logging
import aiohttp
from argus.config import settings
from argus.notifiers.base import BaseNotifier

logger = logging.getLogger(__name__)


class SlackNotifier(BaseNotifier):
    name = "slack"

    def __init__(self):
        self.enabled = bool(settings.SLACK_WEBHOOK_URL)
        self.webhook_url = settings.SLACK_WEBHOOK_URL or ""

    async def send(self, title: str, message: str, severity: str = "info", **kwargs) -> bool:
        if not self.enabled:
            return False
        colors = {"critical": "#FF0000", "high": "#FFA500", "medium": "#FFFF00", "low": "#00FF00", "info": "#0088FF"}
        payload = {
            "attachments": [{
                "color": colors.get(severity, "#0088FF"),
                "title": title,
                "text": message,
                "ts": kwargs.get("timestamp"),
            }]
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as resp:
                    return resp.status == 200
        except Exception as e:
            logger.error(f"Slack send failed: {e}")
            return False

    async def test_connection(self) -> bool:
        return await self.send("Test", "Argus OSINT test notification", "info")
