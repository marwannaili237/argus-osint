"""TheHive case/observable notifier."""
import logging
import aiohttp
from argus.config import settings
from argus.notifiers.base import BaseNotifier

logger = logging.getLogger(__name__)


class TheHiveNotifier(BaseNotifier):
    name = "thehive"

    def __init__(self):
        self.enabled = bool(settings.THEHIVE_URL and settings.THEHIVE_API_KEY)
        self.url = settings.THEHIVE_URL.rstrip("/") if settings.THEHIVE_URL else ""
        self.api_key = settings.THEHIVE_API_KEY or ""

    async def send(self, title: str, message: str, severity: str = "info", **kwargs) -> bool:
        if not self.enabled:
            return False
        tlp_map = {"critical": 3, "high": 2, "medium": 2, "low": 1, "info": 0}
        case_payload = {
            "title": title,
            "description": message,
            "tlp": tlp_map.get(severity, 0),
            "severity": {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(severity, 0),
            "tags": ["argus-osint"],
        }
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{self.url}/api/case", json=case_payload, headers=headers) as resp:
                    if resp.status == 201:
                        case_data = await resp.json()
                        observable_type = kwargs.get("observable_type", "domain")
                        observable_value = kwargs.get("observable_value", "")
                        if observable_value:
                            obs_payload = {"dataType": observable_type, "data": observable_value, "message": f"From Argus OSINT: {title}"}
                            await session.post(f"{self.url}/api/case/{case_data.get('_id', '')}/observable", json=obs_payload, headers=headers)
                    return resp.status in (200, 201)
        except Exception as e:
            logger.error(f"TheHive send failed: {e}")
            return False

    async def test_connection(self) -> bool:
        if not self.enabled:
            return False
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"Bearer {self.api_key}"}
                async with session.get(f"{self.url}/api/case/count", headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    return resp.status == 200
        except Exception:
            return False
