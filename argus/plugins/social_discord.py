"""Discord user information lookup plugin."""
import logging
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class SocialDiscordPlugin(BasePlugin):
    name = "social_discord"
    target_types = ["username"]
    timeout_seconds = 15

    async def run(self, target: str) -> PluginResult:
        """Check for Discord user info. Note: Discord's API requires authentication for
        most lookups, so this plugin checks public-facing endpoints and reports what
        is accessible without auth."""
        # Discord doesn't expose much without auth. We try the public embed endpoint.
        # Real Discord lookups would need a bot token for the Discord API.
        avatar_url = f"https://cdn.discordapp.com/embed/avatars/0.png"
        found = False
        user_id = None

        # Check if target looks like a Discord snowflake ID (17-20 digit number)
        if target.isdigit() and 17 <= len(target) <= 20:
            user_id = target
            # Try the public user profile widget endpoint
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"https://discord.com/api/v10/users/{target}",
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        if resp.status == 200:
                            d = await resp.json()
                            found = True
                            avatar_url = f"https://cdn.discordapp.com/avatars/{target}/{d.get('avatar', '0')}.png"
                        elif resp.status == 401:
                            # Auth required - we know the ID format is valid
                            found = True
            except Exception:
                pass
        else:
            # For usernames, Discord no longer supports discriminator lookups
            # (they migrated to global usernames). We note this limitation.
            pass

        return PluginResult(
            plugin_name=self.name,
            status="success",
            data={
                "username": target,
                "user_id": user_id,
                "found": found,
                "avatar_url": avatar_url,
                "note": "Discord requires authenticated API access for full user lookups. Snowflake IDs may be verified." if not found else "User ID format confirmed.",
            },
        )
