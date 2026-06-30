"""Argus OSINT – DNS History Plugin"""

from __future__ import annotations

import logging

import aiohttp
import dns.resolver

from argus.plugins.runner import BasePlugin, PluginInfo

logger = logging.getLogger(__name__)


class DNSHistoryPlugin(BasePlugin):
    @property
    def info(self) -> PluginInfo:
        return PluginInfo(
            name="dns_history",
            display_name="DNS History",
            description="Query current DNS records and historical DNS data",
            supported_types=["domain"],
            tags=["dns", "recon"],
        )

    async def run(self, target_value: str, target_type: str, **kwargs) -> dict:
        records: dict = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": []}
        for qtype in records:
            try:
                answers = dns.resolver.resolve(target_value, qtype)
                records[qtype] = [str(r) for r in answers]
            except Exception:
                pass

        historical = []
        settings = kwargs.get("settings")
        if settings and getattr(settings, "SECURITYTRAILS_API_KEY", None):
            try:
                async with aiohttp.ClientSession() as session:
                    url = f"https://api.securitytrails.com/v1/domain/{target_value}/dns/history"
                    headers = {"APIKEY": settings.SECURITYTRAILS_API_KEY}
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            historical = data.get("records", [])
            except Exception as e:
                logger.warning("SecurityTrails query failed for %s: %s", target_value, e)

        return {"dns_records": records, "historical": historical}
