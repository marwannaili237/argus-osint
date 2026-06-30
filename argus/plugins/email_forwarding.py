"""Email forwarding detection plugin."""
import logging
import dns.resolver
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class EmailForwardingPlugin(BasePlugin):
    name = "email_forwarding"
    target_types = ["email"]
    timeout_seconds = 15

    async def run(self, target: str) -> PluginResult:
        domain = target.split("@")[-1]
        spf_records = []
        try:
            for r in dns.resolver.resolve(domain, "TXT"):
                txt = str(r).strip('"')
                if "v=spf" in txt.lower():
                    spf_records.append(txt)
        except Exception:
            pass
        forwarding_detected = any("include:" in r for r in spf_records)
        includes = []
        for r in spf_records:
            for part in r.split():
                if part.startswith("include:"):
                    includes.append(part[8:])
        return PluginResult(plugin_name=self.name, status="success", data={"forwarding_detected": forwarding_detected, "forwarding_path": includes, "original_domain": domain, "risk_level": "medium" if forwarding_detected else "low", "spf_records": spf_records})
