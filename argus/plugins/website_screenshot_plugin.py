"""Argus OSINT – Website Screenshot/Metadata Plugin"""

from __future__ import annotations

import logging
import re

import aiohttp

from argus.plugins.runner import BasePlugin, PluginInfo

logger = logging.getLogger(__name__)


class WebsiteScreenshotPlugin(BasePlugin):
    @property
    def info(self) -> PluginInfo:
        return PluginInfo(
            name="website_screenshot",
            display_name="Website Screenshot",
            description="Fetch page metadata (title, description, status)",
            supported_types=["domain", "url"],
            tags=["web", "recon"],
        )

    async def run(self, target_value: str, target_type: str, **kwargs) -> dict:
        url = target_value if target_type == "url" else f"https://{target_value}"
        title = ""
        meta_description = ""
        status_code = 0
        content_length = 0

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15),
                                       ssl=False, allow_redirects=True) as resp:
                    status_code = resp.status
                    content_length = int(resp.headers.get("Content-Length", 0))
                    body = await resp.text(errors="replace")
                    t = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                    if t:
                        title = t.group(1).strip()[:500]
                    d = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\'>]+)',
                                  body, re.IGNORECASE)
                    if not d:
                        d = re.search(r'<meta[^>]+content=["\']([^"\'>]+)["\'][^>]+name=["\']description["\']',
                                      body, re.IGNORECASE)
                    if d:
                        meta_description = d.group(1).strip()[:1000]
        except Exception as e:
            logger.warning("Failed to fetch %s: %s", url, e)

        return {
            "screenshot_url": "mock",
            "title": title,
            "meta_description": meta_description,
            "status_code": status_code,
            "content_length": content_length,
        }
