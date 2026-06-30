"""Enhanced email reputation checking plugin."""
import logging
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult
from argus.config import settings

logger = logging.getLogger(__name__)


class EmailReputationEnhancedPlugin(BasePlugin):
    name = "email_reputation_enhanced"
    target_types = ["email"]
    timeout_seconds = 20

    async def run(self, target: str) -> PluginResult:
        score = 50.0
        sources = {}
        if settings.VIRUSTOTAL_API_KEY:
            try:
                url = f"https://www.virustotal.com/api/v3/search?query={target}"
                headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        if resp.status == 200:
                            d = await resp.json()
                            sources["virustotal"] = {"found": bool(d.get("data")), "detections": d.get("meta", {}).get("count", 0)}
                            if d.get("data"):
                                score -= 20
            except Exception:
                sources["virustotal"] = {"error": "request failed"}
        domain = target.split("@")[-1]
        import dns.resolver
        spf_ok = False
        try:
            for r in dns.resolver.resolve(domain, "TXT"):
                if "v=spf" in str(r).lower():
                    spf_ok = True
                    break
        except Exception:
            pass
        sources["spf"] = {"present": spf_ok}
        if not spf_ok:
            score -= 10
        dmarc_ok = False
        try:
            for r in dns.resolver.resolve(f"_dmarc.{domain}", "TXT"):
                if "v=dmarc" in str(r).lower():
                    dmarc_ok = True
                    break
        except Exception:
            pass
        sources["dmarc"] = {"present": dmarc_ok}
        if not dmarc_ok:
            score -= 10
        score = max(0, min(100, score))
        return PluginResult(plugin_name=self.name, status="success", data={"reputation_score": score, "sources": sources, "breach_count": 0})
