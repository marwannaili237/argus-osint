"""Broken link detection plugin."""
import asyncio
import logging
import aiohttp
from urllib.parse import urlparse, urljoin
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)

MAX_CHECK = 100


class WebBrokenLinksPlugin(BasePlugin):
    name = "web_broken_links"
    target_types = ["domain", "url"]
    timeout_seconds = 60

    async def _check_link(self, session: aiohttp.ClientSession, url: str) -> dict:
        """Check a single link for broken status."""
        try:
            async with session.head(
                url, timeout=aiohttp.ClientTimeout(total=5),
                allow_redirects=True, ssl=False,
            ) as resp:
                if resp.status >= 400:
                    return {"url": url, "status_code": resp.status, "error": f"HTTP {resp.status}"}
                return None  # Not broken
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            return {"url": url, "status_code": 0, "error": str(e)[:100]}

    async def run(self, target: str) -> PluginResult:
        """Fetch a page, extract all links, and check each for broken status."""
        base_url = target if target.startswith("http") else f"https://{target}"
        parsed_base = urlparse(base_url)

        # First, fetch the page to extract links
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    base_url, timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False, allow_redirects=True,
                ) as resp:
                    if resp.status != 200:
                        return PluginResult(
                            plugin_name=self.name, status="error", data={},
                            error_message=f"Could not fetch page: HTTP {resp.status}",
                        )
                    body = await resp.text()

        except Exception as e:
            return PluginResult(
                plugin_name=self.name, status="error", data={},
                error_message=str(e),
            )

        # Extract links from the page
        import re
        link_pattern = re.compile(r'href=["\']((https?://|/)[^"\'\s]+)["\']', re.IGNORECASE)
        all_links = set()
        for m in link_pattern.finditer(body):
            href = m.group(1)
            if href.startswith("/"):
                href = urljoin(base_url, href)
            parsed = urlparse(href)
            if parsed.scheme in ("http", "https"):
                all_links.add(href.split("#")[0].split("?")[0])

        # Limit checks
        links_to_check = list(all_links)[:MAX_CHECK]

        # Check all links concurrently (in batches)
        broken = []
        healthy = 0
        redirects = []
        batch_size = 20

        async with aiohttp.ClientSession() as session:
            for i in range(0, len(links_to_check), batch_size):
                batch = links_to_check[i:i + batch_size]
                tasks = [self._check_link(session, url) for url in batch]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for r in results:
                    if isinstance(r, dict) and r is not None:
                        broken.append(r)
                    elif r is None:
                        healthy += 1

        return PluginResult(
            plugin_name=self.name, status="success",
            data={
                "total_links": len(all_links),
                "links_checked": len(links_to_check),
                "broken_links": broken,
                "broken_count": len(broken),
                "healthy_links": healthy,
                "redirect_chains": redirects,
                "broken_percentage": round(len(broken) / max(len(links_to_check), 1) * 100, 1),
            },
        )
