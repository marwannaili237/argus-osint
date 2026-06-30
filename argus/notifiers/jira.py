"""Jira REST API notifier."""
import logging
import aiohttp
from argus.config import settings
from argus.notifiers.base import BaseNotifier

logger = logging.getLogger(__name__)


class JiraNotifier(BaseNotifier):
    name = "jira"

    def __init__(self):
        self.enabled = bool(settings.JIRA_URL and settings.JIRA_TOKEN)
        self.url = settings.JIRA_URL.rstrip("/") if settings.JIRA_URL else ""
        self.token = settings.JIRA_TOKEN or ""

    async def send(self, title: str, message: str, severity: str = "info", **kwargs) -> bool:
        if not self.enabled:
            return False
        priority_map = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "info": "Lowest"}
        payload = {
            "fields": {
                "project": {"key": kwargs.get("project_key", "SEC")},
                "summary": f"[Argus OSINT] {title}",
                "description": message,
                "issuetype": {"name": kwargs.get("issue_type", "Bug")},
                "priority": {"name": priority_map.get(severity, "Low")},
            }
        }
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{self.url}/rest/api/2/issue", json=payload, headers=headers) as resp:
                    return resp.status == 201
        except Exception as e:
            logger.error(f"Jira send failed: {e}")
            return False

    async def test_connection(self) -> bool:
        if not self.enabled:
            return False
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"Bearer {self.token}"}
                async with session.get(f"{self.url}/rest/api/2/myself", headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    return resp.status == 200
        except Exception:
            return False
