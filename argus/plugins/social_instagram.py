"""Instagram profile lookup plugin."""
import re
import logging
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class SocialInstagramPlugin(BasePlugin):
    name = "social_instagram"
    target_types = ["username"]
    timeout_seconds = 15

    async def run(self, target: str) -> PluginResult:
        """Look up an Instagram user's public profile."""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
                async with session.get(
                    f"https://www.instagram.com/{target}/",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    text = await resp.text()

                    # Parse shared data from page source
                    found = False
                    full_name = ""
                    bio = ""
                    followers = 0
                    following = 0
                    is_private = False
                    is_verified = False
                    post_count = 0

                    # Try to find JSON data embedded in the page
                    data_match = re.search(r'"edge_followed_by"\s*:\s*\{"count"\s*:\s*(\d+)', text)
                    if data_match:
                        found = True
                        followers = int(data_match.group(1))

                    following_match = re.search(r'"edge_follow"\s*:\s*\{"count"\s*:\s*(\d+)', text)
                    if following_match:
                        following = int(following_match.group(1))

                    bio_match = re.search(r'"biography"\s*:\s*"([^"]*?)"', text)
                    if bio_match:
                        bio = bio_match.group(1)

                    name_match = re.search(r'"full_name"\s*:\s*"([^"]*?)"', text)
                    if name_match:
                        full_name = name_match.group(1)

                    private_match = re.search(r'"is_private"\s*:\s*(true|false)', text)
                    if private_match:
                        is_private = private_match.group(1) == "true"

                    verified_match = re.search(r'"is_verified"\s*:\s*(true|false)', text)
                    if verified_match:
                        is_verified = verified_match.group(1) == "true"

                    count_match = re.search(r'"edge_owner_to_timeline_media"\s*:\s*\{"count"\s*:\s*(\d+)', text)
                    if count_match:
                        post_count = int(count_match.group(1))

                    return PluginResult(
                        plugin_name=self.name,
                        status="success",
                        data={
                            "username": target,
                            "full_name": full_name,
                            "bio": bio,
                            "followers": followers,
                            "following": following,
                            "post_count": post_count,
                            "is_private": is_private,
                            "is_verified": is_verified,
                            "profile_url": f"https://instagram.com/{target}",
                            "found": found,
                        },
                    )
        except Exception as e:
            logger.error(f"Instagram lookup failed: {e}")
            return PluginResult(
                plugin_name=self.name, status="error",
                data={"username": target, "found": False},
                error_message=str(e),
            )
