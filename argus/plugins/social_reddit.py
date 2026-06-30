"""Reddit user profile lookup plugin."""
import logging
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class SocialRedditPlugin(BasePlugin):
    name = "social_reddit"
    target_types = ["username"]
    timeout_seconds = 15

    async def run(self, target: str) -> PluginResult:
        """Look up a Reddit user's public profile via the JSON API."""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"User-Agent": "ArgusOSINT/2.0 (research tool)"}
                async with session.get(
                    f"https://www.reddit.com/user/{target}/about.json",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        d = await resp.json()
                        data = d.get("data", {})
                        return PluginResult(
                            plugin_name=self.name,
                            status="success",
                            data={
                                "username": data.get("name", target),
                                "link_karma": data.get("link_karma", 0),
                                "comment_karma": data.get("comment_karma", 0),
                                "total_karma": (data.get("link_karma", 0) or 0) + (data.get("comment_karma", 0) or 0),
                                "account_age_days": data.get("account_age_days", 0),
                                "created_utc": data.get("created_utc"),
                                "is_gold": data.get("is_gold", False),
                                "is_mod": data.get("is_mod", False),
                                "has_verified_email": data.get("has_verified_email", False),
                                "profile_url": f"https://reddit.com/user/{target}",
                                "found": True,
                            },
                        )
                    elif resp.status == 404:
                        return PluginResult(
                            plugin_name=self.name, status="success",
                            data={"username": target, "found": False, "profile_url": f"https://reddit.com/user/{target}"},
                        )
                    else:
                        return PluginResult(
                            plugin_name=self.name, status="error", data={},
                            error_message=f"Reddit API returned HTTP {resp.status}",
                        )
        except aiohttp.ClientError as e:
            logger.error(f"Reddit lookup failed: {e}")
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message=str(e))
