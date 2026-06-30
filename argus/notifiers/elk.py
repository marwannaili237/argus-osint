"""Elasticsearch/ELK notifier."""
import logging
import aiohttp
import json
from datetime import datetime, timezone
from argus.config import settings
from argus.notifiers.base import BaseNotifier

logger = logging.getLogger(__name__)


class ELKNotifier(BaseNotifier):
    name = "elk"

    def __init__(self):
        self.enabled = bool(settings.ELASTICSEARCH_URL)
        self.es_url = settings.ELASTICSEARCH_URL.rstrip("/") if settings.ELASTICSEARCH_URL else ""

    async def send(self, title: str, message: str, severity: str = "info", **kwargs) -> bool:
        if not self.enabled:
            return False
        index = kwargs.get("index", f"argus-osint-{datetime.now(timezone.utc).strftime('%Y.%m')}")
        doc = {"@timestamp": datetime.now(timezone.utc).isoformat(), "severity": severity, "title": title, "message": message, "source": "argus-osint", **kwargs}
        url = f"{self.es_url}/{index}/_doc"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=doc) as resp:
                    return resp.status in (200, 201)
        except Exception as e:
            logger.error(f"ELK send failed: {e}")
            return False

    async def test_connection(self) -> bool:
        if not self.enabled:
            return False
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.es_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    return resp.status == 200
        except Exception:
            return False
