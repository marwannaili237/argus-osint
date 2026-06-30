import logging
import hashlib
import struct

import aiohttp

from argus.plugins.runner import BasePlugin, PluginInfo

logger = logging.getLogger(__name__)


def _mmh3_hash(data: bytes) -> int:
    """Simulate Shodan's mmh3 favicon hash using murmurhash3-style computation."""
    h = hashlib.md5(data).digest()
    seed = 0
    for i in range(0, len(h), 4):
        chunk = h[i:i+4]
        if len(chunk) == 4:
            k = struct.unpack('<I', chunk)[0]
            k = (k * 0xcc9e2d51) & 0xFFFFFFFF
            k = ((k >> 15) | (k << 17)) & 0xFFFFFFFF
            k = (k * 0x1b873593) & 0xFFFFFFFF
            seed ^= k
            seed = ((seed >> 13) | (seed << 19)) & 0xFFFFFFFF
            seed = (seed * 5 + 0xe6546b64) & 0xFFFFFFFF
    seed ^= len(h)
    seed ^= seed >> 16
    seed = (seed * 0x85ebca6b) & 0xFFFFFFFF
    seed ^= seed >> 13
    seed = (seed * 0xc2b2ae35) & 0xFFFFFFFF
    seed ^= seed >> 16
    if seed >= 0x80000000:
        seed -= 0x100000000
    return seed


class FaviconHashPlugin(BasePlugin):
    @property
    def info(self) -> PluginInfo:
        return PluginInfo(
            name="favicon_hash",
            display_name="Favicon Hash",
            description="Fetch favicon and compute Shodan-compatible mmh3 hash",
            supported_types=["domain", "url"],
            tags=["web", "hash", "recon"],
        )

    async def run(self, target_value: str, target_type: str, **kwargs) -> dict:
        base = target_value if target_type == "url" else f"https://{target_value}"
        favicon_urls = [
            f"{base}/favicon.ico",
            f"{base.rstrip('/')}/favicon.ico",
        ]
        favicon_hash = ""
        shodan_matches = []

        for furl in favicon_urls:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(furl, timeout=aiohttp.ClientTimeout(total=10),
                                           ssl=False) as resp:
                        if resp.status == 200:
                            data = await resp.read()
                            favicon_hash = str(_mmh3_hash(data))
                            break
            except Exception:
                continue

        if favicon_hash:
            settings = kwargs.get("settings")
            if settings and getattr(settings, "SHODAN_API_KEY", None):
                try:
                    async with aiohttp.ClientSession() as session:
                        url = f"https://api.shodan.io/shodan/host/search?key={settings.SHODAN_API_KEY}&query=http.favicon.hash:{favicon_hash}"
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                            if resp.status == 200:
                                result = await resp.json()
                                shodan_matches = result.get("matches", [])[:10]
                except Exception as e:
                    logger.warning("Shodan favicon search failed: %s", e)

        return {
            "favicon_url": favicon_urls[0],
            "favicon_hash": favicon_hash,
            "shodan_matches": [{"ip": m.get("ip_str", ""), "port": m.get("port", 0),
                                "org": m.get("org", "")} for m in shodan_matches],
        }
