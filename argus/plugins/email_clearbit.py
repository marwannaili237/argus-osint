"""Clearbit email enrichment plugin."""
import logging
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult
from argus.config import settings

logger = logging.getLogger(__name__)


class EmailClearbitPlugin(BasePlugin):
    name = "email_clearbit"
    target_types = ["email"]
    timeout_seconds = 15

    async def run(self, target: str) -> PluginResult:
        if not settings.CLEARBIT_API_KEY:
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message="CLEARBIT_API_KEY not set")
        url = f"https://person.clearbit.com/v2/people/find?email={target}"
        headers = {"Authorization": f"Bearer {settings.CLEARBIT_API_KEY}"}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=self.timeout_seconds)) as resp:
                    if resp.status == 200:
                        d = await resp.json()
                        person = d.get("person", {})
                        company = d.get("company", {})
                        return PluginResult(plugin_name=self.name, status="success", data={"person": {"name": person.get("fullName"), "email": person.get("email"), "title": person.get("title"), "company": person.get("employment", {}).get("name")}, "company": {"name": company.get("name"), "domain": company.get("domain"), "metrics": company.get("metrics")}})
                    return PluginResult(plugin_name=self.name, status="error", data={}, error_message=f"HTTP {resp.status}")
        except Exception as e:
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message=str(e))
