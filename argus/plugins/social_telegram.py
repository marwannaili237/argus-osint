"""Telegram public channel/user lookup plugin."""
import logging
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class SocialTelegramPlugin(BasePlugin):
    name = "social_telegram"
    target_types = ["username"]
    timeout_seconds = 15

    async def run(self, target: str) -> PluginResult:
        """Check if a Telegram username has a public profile or channel."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://t.me/{target}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    text = await resp.text()
                    # Check for indicators of a valid public profile/channel
                    found = False
                    display_name = ""
                    bio = ""
                    subscriber_count = 0
                    is_channel = False
                    if 'tgme_page_title' in text and target.lower() in text.lower():
                        found = True
                    if 'tgme_page_extra' in text:
                        import re
                        m = re.search(r'tgme_page_extra">(@[^<]+)<', text)
                        if m:
                            pass  # username confirmed
                        sub_m = re.search(r'(\d[\d\s]*)\s*(subscribers|members)', text)
                        if sub_m:
                            subscriber_count = int(sub_m.group(1).replace(" ", ""))
                        if 'subscribers' in text.lower():
                            is_channel = True
                        title_m = re.search(r'<div class="tgme_page_title"[^>]*><span dir="auto">([^<]+)</span>', text)
                        if title_m:
                            display_name = title_m.group(1).strip()
                        bio_m = re.search(r'<div class="tgme_page_description"[^>]*>([^<]+)</div>', text)
                        if bio_m:
                            bio = bio_m.group(1).strip()
                    return PluginResult(
                        plugin_name=self.name,
                        status="success",
                        data={
                            "found": found,
                            "username": target,
                            "url": url,
                            "display_name": display_name,
                            "bio": bio,
                            "subscriber_count": subscriber_count,
                            "is_channel": is_channel,
                        }
                    )
        except Exception as e:
            logger.error(f"Telegram lookup failed: {e}")
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message=str(e))
