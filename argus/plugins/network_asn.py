"""ASN lookup plugin using ip-api.com."""
import logging
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class NetworkASNPlugin(BasePlugin):
    name = "network_asn"
    target_types = ["ip"]
    timeout_seconds = 15

    async def run(self, target: str) -> PluginResult:
        """Query ASN information for an IP address via ip-api.com free API."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://ip-api.com/json/{target}?fields=as,asname,org,isp,query,country,city,lat,lon",
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        d = await resp.json()
                        if d.get("status") == "success":
                            asn_str = d.get("as", "")
                            asn_num = ""
                            if "/" in asn_str:
                                asn_num = asn_str.split("/")[0].replace("AS", "")
                            return PluginResult(
                                plugin_name=self.name, status="success",
                                data={
                                    "asn": asn_str,
                                    "asn_number": asn_num,
                                    "as_name": d.get("asname", ""),
                                    "as_org": d.get("org", ""),
                                    "isp": d.get("isp", ""),
                                    "country": d.get("country", ""),
                                    "city": d.get("city", ""),
                                    "lat": d.get("lat"),
                                    "lon": d.get("lon"),
                                    "prefix": f"{d.get('lat')},{d.get('lon')}" if d.get("lat") else "",
                                },
                            )
                        return PluginResult(
                            plugin_name=self.name, status="error", data={},
                            error_message=d.get("message", "Unknown error from ip-api.com"),
                        )
                    return PluginResult(
                        plugin_name=self.name, status="error", data={},
                        error_message=f"ip-api.com returned HTTP {resp.status}",
                    )
        except Exception as e:
            logger.error(f"ASN lookup failed: {e}")
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message=str(e))