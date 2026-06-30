"""Argus OSINT – IP Geolocation Plugin"""

from __future__ import annotations

import logging

import aiohttp

from argus.plugins.runner import BasePlugin, PluginInfo

logger = logging.getLogger(__name__)


class IPGeolocationPlugin(BasePlugin):
    @property
    def info(self) -> PluginInfo:
        return PluginInfo(
            name="ip_geolocation",
            display_name="IP Geolocation",
            description="Geolocate an IP address using ip-api.com",
            supported_types=["ip"],
            tags=["ip", "geo", "recon"],
        )

    async def run(self, target_value: str, target_type: str, **kwargs) -> dict:
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://ip-api.com/json/{target_value}?fields=status,country,regionName,city,lat,lon,isp,org,as,query"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    data = await resp.json()
                    if data.get("status") == "success":
                        return {
                            "country": data.get("country", ""),
                            "city": data.get("city", ""),
                            "region": data.get("regionName", ""),
                            "lat": data.get("lat", 0.0),
                            "lon": data.get("lon", 0.0),
                            "isp": data.get("isp", ""),
                            "org": data.get("org", ""),
                            "as": data.get("as", ""),
                        }
                    return {"error": data.get("message", "Lookup failed"), "country": "", "city": "",
                            "region": "", "lat": 0.0, "lon": 0.0, "isp": "", "org": "", "as": ""}
        except Exception as e:
            logger.error("Geolocation failed for %s: %s", target_value, e)
            return {"error": str(e), "country": "", "city": "", "region": "",
                    "lat": 0.0, "lon": 0.0, "isp": "", "org": "", "as": ""}