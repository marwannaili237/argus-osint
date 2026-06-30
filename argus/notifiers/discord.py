"""Discord webhook notifier."""
import logging
import aiohttp
from argus.config import settings
from argus.notifiers.base import BaseNotifier

logger = logging.getLogger(__name__)


class DiscordNotifier(BaseNotifier):
    name = "discord"

    def __init__(self):
        self.enabled = bool(settings.DISCORD_WEBHOOK_URL)
        self.webhook_url = settings.DISCORD_WEBHOOK_URL or ""

    async def send(self, title: str, message: str, severity: str = "info", **kwargs) -> bool:
        if not self.enabled:
            return False
        colors = {"critical": 0xFF0000, "high": 0xFFA500, "medium": 0xFFFF00, "low": 0x00FF00, "info": 0x0088FF}
        payload = {
            "embeds": [{
                "title": title,
                "description": message,
                "color": colors.get(severity, 0x0088FF),
                "timestamp": kwargs.get("timestamp", ""),
            }]
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as resp:
                    return resp.status == 204
        except Exception as e:
            logger.error(f"Discord send failed: {e}")
            return False

    async def test_connection(self) -> bool:
        return await self.send("Test", "Argus OSINT test notification", "info")
