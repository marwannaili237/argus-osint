"""Wayback Machine web archive plugin."""
import logging
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class WebArchivePlugin(BasePlugin):
    name = "web_archive"
    target_types = ["domain", "url"]
    timeout_seconds = 20

    async def run(self, target: str) -> PluginResult:
        """Query the Wayback Machine CDX API for historical snapshots of a URL or domain."""
        url = target if target.startswith("http") else f"https://{target}"
        api_url = "http://web.archive.org/cdx/search/cdx"
        params = {
            "url": url,
            "output": "json",
            "fl": "timestamp,original,statuscode,mimetype",
            "limit": 100,
            "collapse": "timestamp:6",  # Collapse to monthly
            "filter": "statuscode:200",
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    api_url, params=params,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        # First row is the header
                        if len(data) < 2:
                            return PluginResult(
                                plugin_name=self.name, status="success",
                                data={"archive_count": 0, "snapshots": [], "wayback_url": f"https://web.archive.org/web/*/{url}"},
                            )

                        header = data[0]
                        rows = data[1:]
                        snapshots = []
                        for row in rows:
                            snapshots.append({
                                "timestamp": row[0] if len(row) > 0 else "",
                                "url": row[1] if len(row) > 1 else "",
                                "status_code": int(row[2]) if len(row) > 2 else 0,
                                "mime_type": row[3] if len(row) > 3 else "",
                                "wayback_url": f"https://web.archive.org/web/{row[0] if len(row) > 0 else ''}/{row[1] if len(row) > 1 else ''}",
                            })

                        first_archive = snapshots[-1]["timestamp"] if snapshots else ""
                        last_archive = snapshots[0]["timestamp"] if snapshots else ""

                        return PluginResult(
                            plugin_name=self.name, status="success",
                            data={
                                "archive_count": len(snapshots),
                                "first_archive": first_archive,
                                "last_archive": last_archive,
                                "recent_snapshots": snapshots[:20],
                                "archive_urls": [s["wayback_url"] for s in snapshots[:10]],
                                "wayback_search_url": f"https://web.archive.org/web/*/{url}",
                            },
                        )
                    return PluginResult(
                        plugin_name=self.name, status="error", data={},
                        error_message=f"Wayback Machine API returned HTTP {resp.status}",
                    )
        except Exception as e:
            logger.error(f"Web Archive lookup failed: {e}")
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message=str(e))
