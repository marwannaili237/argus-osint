"""Microsoft Teams webhook notifier."""
import logging
import aiohttp
from argus.config import settings
from argus.notifiers.base import BaseNotifier

logger = logging.getLogger(__name__)


class TeamsNotifier(BaseNotifier):
    name = "teams"

    def __init__(self):
        self.enabled = bool(settings.TEAMS_WEBHOOK_URL)
        self.webhook_url = settings.TEAMS_WEBHOOK_URL or ""

    async def send(self, title: str, message: str, severity: str = "info", **kwargs) -> bool:
        if not self.enabled:
            return False
        colors = {"critical": "FF0000", "high": "FFA500", "medium": "FFFF00", "low": "00CC00", "info": "0088FF"}
        card = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.2",
                    "body": [
                        {"type": "TextBlock", "text": title, "size": "Large", "weight": "Bolder"},
                        {"type": "TextBlock", "text": message, "wrap": True},
                        {"type": "FactSet", "facts": [{"title": "Severity", "value": severity.upper()}, {"title": "Source", "value": "Argus OSINT"}]},
                    ],
                },
            }],
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=card) as resp:
                    return resp.status == 200
        except Exception as e:
            logger.error(f"Teams send failed: {e}")
            return False

    async def test_connection(self) -> bool:
        return await self.send("Test", "Argus OSINT test notification", "info")
