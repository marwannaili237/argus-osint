"""OpenCTI notifier for creating observables and indicators."""
import logging
import aiohttp
from argus.config import settings
from argus.notifiers.base import BaseNotifier

logger = logging.getLogger(__name__)


class OpenCTINotifier(BaseNotifier):
    name = "opencti"

    def __init__(self):
        self.enabled = bool(settings.OPENCTI_URL and settings.OPENCTI_TOKEN)
        self.url = settings.OPENCTI_URL.rstrip("/") if settings.OPENCTI_URL else ""
        self.token = settings.OPENCTI_TOKEN or ""

    async def send(self, title: str, message: str, severity: str = "info", **kwargs) -> bool:
        if not self.enabled:
            return False
        observable_type = kwargs.get("observable_type", "Domain-Name")
        observable_value = kwargs.get("observable_value", "")
        if not observable_value:
            return False
        type_map = {"domain": "Domain-Name", "ip": "IPv4-Address", "email": "Email-Address", "url": "Url", "hash": "StixFile"}
        stix_type = type_map.get(observable_type, "Domain-Name")
        confidence = {"critical": 90, "high": 75, "medium": 50, "low": 25, "info": 10}.get(severity, 50)
        payload = {
            "type": stix_type,
            "value": observable_value,
            "confidence": confidence,
            "x_opencti_description": f"{title}: {message}",
            "objectMarking": [{"definition_type": "TLP", "definition": ["TLP:CLEAR"]}],
        }
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{self.url}/api/observables", json=payload, headers=headers) as resp:
                    return resp.status in (200, 201)
        except Exception as e:
            logger.error(f"OpenCTI send failed: {e}")
            return False

    async def test_connection(self) -> bool:
        if not self.enabled:
            return False
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"Bearer {self.token}"}
                async with session.get(f"{self.url}/api/health", headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    return resp.status == 200
        except Exception:
            return False
