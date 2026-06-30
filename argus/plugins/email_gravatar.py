"""Gravatar profile lookup plugin."""
import hashlib
import logging
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class EmailGravatarPlugin(BasePlugin):
    name = "email_gravatar"
    target_types = ["email"]
    timeout_seconds = 10

    async def run(self, target: str) -> PluginResult:
        email_hash = hashlib.md5(target.strip().lower().encode()).hexdigest()
        profile_url = f"https://www.gravatar.com/{email_hash}"
        gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
        has_profile = False
        display_name = None
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://www.gravatar.com/{email_hash}.json", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        entry = data.get("entry", [{}])
                        if entry:
                            has_profile = True
                            display_name = entry[0].get("displayName")
                            profile_url = entry[0].get("profileUrl", profile_url)
        except Exception:
            pass
        return PluginResult(plugin_name=self.name, status="success", data={"gravatar_url": gravatar_url, "profile_url": profile_url, "has_profile": has_profile, "display_name": display_name})
