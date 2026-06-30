"""Mattermost webhook notifier."""
import logging
import aiohttp
from argus.config import settings
from argus.notifiers.base import BaseNotifier

logger = logging.getLogger(__name__)


class MattermostNotifier(BaseNotifier):
    name = "mattermost"

    def __init__(self):
        self.enabled = bool(settings.MATTERMOST_WEBHOOK_URL)
        self.webhook_url = settings.MATTERMOST_WEBHOOK_URL or ""

    async def send(self, title: str, message: str, severity: str = "info", **kwargs) -> bool:
        if not self.enabled:
            return False
        payload = {"text": f"**{title}**
{message}", "username": "Argus OSINT", "icon_url": kwargs.get("icon_url", "")}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as resp:
                    return resp.status == 200
        except Exception as e:
            logger.error(f"Mattermost send failed: {e}")
            return False

    async def test_connection(self) -> bool:
        return await self.send("Test", "Argus OSINT test notification", "info")
