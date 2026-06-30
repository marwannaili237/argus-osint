"""Twitter/X profile lookup plugin."""
import re
import logging
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class SocialTwitterPlugin(BasePlugin):
    name = "social_twitter"
    target_types = ["username"]
    timeout_seconds = 15

    async def run(self, target: str) -> PluginResult:
        """Look up a Twitter/X user profile via syndication endpoint."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://syndication.twitter.com/srv/timeline-profile/screen-name/{target}"
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
                ) as resp:
                    if resp.status == 200:
                        text = await resp.text()

                        display_name = ""
                        m = re.search(r'"fullName"\s*:\s*"([^"]+)"', text)
                        if m:
                            display_name = m.group(1)

                        bio = ""
                        m = re.search(r'"description"\s*:\s*"([^"]*)"', text)
                        if m:
                            bio = m.group(1)

                        followers = 0
                        m = re.search(r'"followersCount"\s*:\s*(\d+)', text)
                        if m:
                            followers = int(m.group(1))

                        following = 0
                        m = re.search(r'"friendsCount"\s*:\s*(\d+)', text)
                        if m:
                            following = int(m.group(1))

                        tweets_count = 0
                        m = re.search(r'"statusesCount"\s*:\s*(\d+)', text)
                        if m:
                            tweets_count = int(m.group(1))

                        verified = False
                        if 'verified' in text.lower() or '"isBlueVerified"' in text:
                            verified = True

                        avatar = ""
                        m = re.search(r'"profileImage400x400"\s*:\s*"([^"]+)"', text)
                        if m:
                            avatar = m.group(1)

                        found = bool(display_name) or 'tgme_page_title' in text or 'timeline-profile' in text

                        return PluginResult(
                            plugin_name=self.name,
                            status="success",
                            data={
                                "username": target,
                                "display_name": display_name,
                                "bio": bio,
                                "followers": followers,
                                "following": following,
                                "tweets_count": tweets_count,
                                "verified": verified,
                                "avatar": avatar,
                                "profile_url": f"https://twitter.com/{target}",
                                "found": found,
                            },
                        )
                    return PluginResult(
                        plugin_name=self.name, status="success",
                        data={"username": target, "found": False, "profile_url": f"https://twitter.com/{target}"},
                    )
        except Exception as e:
            logger.error(f"Twitter lookup failed: {e}")
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message=str(e))
