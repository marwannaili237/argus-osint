"""FullContact email enrichment plugin."""
import logging
import hashlib
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult
from argus.config import settings

logger = logging.getLogger(__name__)


class EmailFullContactPlugin(BasePlugin):
    name = "email_fullcontact"
    target_types = ["email"]
    timeout_seconds = 15

    async def run(self, target: str) -> PluginResult:
        if not settings.FULLCONTACT_API_KEY:
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message="FULLCONTACT_API_KEY not set")
        md5 = hashlib.md5(target.strip().lower().encode()).hexdigest()
        url = f"https://api.fullcontact.com/v3/person.md5/{md5}"
        headers = {"Authorization": f"Bearer {settings.FULLCONTACT_API_KEY}"}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=self.timeout_seconds)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        profiles = []
                        for k, v in (data.get("socialProfiles") or {}).items():
                            if isinstance(v, dict) and v.get("url"):
                                profiles.append({"platform": k, "url": v["url"]})
                        org = data.get("organizations", [{}])[0] if data.get("organizations") else {}
                        return PluginResult(plugin_name=self.name, status="success", data={"social_profiles": profiles, "name": data.get("fullName"), "organization": org.get("name"), "title": org.get("title")})
                    return PluginResult(plugin_name=self.name, status="error", data={}, error_message=f"HTTP {resp.status}")
        except Exception as e:
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message=str(e))
