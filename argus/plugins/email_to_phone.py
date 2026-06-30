"""Email-to-phone correlation plugin."""
import logging
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class EmailToPhonePlugin(BasePlugin):
    name = "email_to_phone"
    target_types = ["email"]
    timeout_seconds = 15

    async def run(self, target: str) -> PluginResult:
        phones = []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://api.fullcontact.com/v3/person.md5/{__import__('hashlib').md5(target.strip().lower().encode()).hexdigest()}", headers={"Authorization": f"Bearer {settings.FULLCONTACT_API_KEY}" if hasattr(settings, 'FULLCONTACT_API_KEY') and settings.FULLCONTACT_API_KEY else ""}, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        d = await resp.json()
                        for p in d.get("phones", []):
                            phones.append({"number": p.get("number"), "type": p.get("type")})
        except Exception:
            pass
        return PluginResult(plugin_name=self.name, status="success", data={"phones_found": phones, "sources": ["fullcontact"] if phones else [], "confidence": 0.7 if phones else 0.0})


from argus.config import settings
