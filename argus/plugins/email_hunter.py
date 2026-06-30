"""Hunter.io email verification plugin."""
import logging
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult
from argus.config import settings

logger = logging.getLogger(__name__)


class EmailHunterPlugin(BasePlugin):
    name = "email_hunter"
    target_types = ["email"]
    timeout_seconds = 15

    async def run(self, target: str) -> PluginResult:
        if not settings.HUNTER_API_KEY:
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message="HUNTER_API_KEY not set")
        url = "https://api.hunter.io/v2/email-verifier"
        params = {"email": target, "api_key": settings.HUNTER_API_KEY}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=self.timeout_seconds)) as resp:
                    if resp.status == 200:
                        d = await resp.json()
                        r = d.get("data", {})
                        return PluginResult(plugin_name=self.name, status="success", data={"email_verification": {"result": r.get("result"), "score": r.get("score"), "regex": r.get("regexp"), "smtp": r.get("smtp_server"), "mx": r.get("mx_records")}, "company": r.get("company"), "department": r.get("department"), "seniority": r.get("seniority")})
                    return PluginResult(plugin_name=self.name, status="error", data={}, error_message=f"HTTP {resp.status}")
        except Exception as e:
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message=str(e))
