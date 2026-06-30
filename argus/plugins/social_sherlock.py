"""Sherlock-style social media account finder."""
import asyncio
import logging
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)

SITES = {
    "twitter": "https://twitter.com/{}", "instagram": "https://instagram.com/{}",
    "reddit": "https://reddit.com/user/{}", "github": "https://github.com/{}",
    "linkedin": "https://linkedin.com/in/{}", "facebook": "https://facebook.com/{}",
    "youtube": "https://youtube.com/{}", "tiktok": "https://tiktok.com/@{}",
    "pinterest": "https://pinterest.com/{}", "twitch": "https://twitch.tv/{}",
    "medium": "https://medium.com/@{}", "keybase": "https://keybase.io/{}",
    "mastodon": "https://mastodon.social/@{}", "dev.to": "https://dev.to/{}",
    "about.me": "https://about.me/{}", "gravatar": "https://gravatar.com/{}",
    "steam": "https://steamcommunity.com/id/{}", "xbox": "https://xboxgamertag.com/{}",
    "psn": "https://psnprofiles.com/{}", "spotify": "https://open.spotify.com/user/{}",
    "soundcloud": "https://soundcloud.com/{}", "flickr": "https://flickr.com/people/{}",
    "vimeo": "https://vimeo.com/{}", "tumblr": "https://{}.tumblr.com",
    "patreon": "https://patreon.com/{}", "buymeacoffee": "https://buymeacoffee.com/{}",
    "ko-fi": "https://ko-fi.com/{}", "substack": "https://{}.substack.com",
    "discord": "https://discord.com/users/{}", "telegram": "https://t.me/{}",
}


class SocialSherlockPlugin(BasePlugin):
    name = "social_sherlock"
    target_types = ["username"]
    timeout_seconds = 60

    async def _check_site(self, session, platform, url_tpl, username):
        url = url_tpl.format(username)
        try:
            async with session.head(url, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=False) as resp:
                if resp.status in (200, 301, 302, 303, 307, 308):
                    return {"platform": platform, "url": url, "status_code": resp.status}
        except Exception:
            pass
        return None

    async def run(self, target: str) -> PluginResult:
        found = []
        async with aiohttp.ClientSession() as session:
            tasks = [self._check_site(session, p, u, target) for p, u in SITES.items()]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, dict):
                    found.append(r)
        return PluginResult(plugin_name=self.name, status="success", data={"profiles_found": found, "total_checked": len(SITES)})
