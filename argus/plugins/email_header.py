"""Email header analysis plugin."""
import re
import logging
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class EmailHeaderPlugin(BasePlugin):
    name = "email_header"
    target_types = ["email"]
    timeout_seconds = 10

    async def run(self, target: str) -> PluginResult:
        if not re.match(r"^[\w.-]+@[\w.-]+\.\w+$", target):
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message="Not a valid email for header analysis")
        domain = target.split("@")[-1]
        import dns.resolver
        received = []
        try:
            answers = dns.resolver.resolve(domain, "MX")
            received = [{"server": str(r.exchange).rstrip("."), "priority": r.preference} for r in answers]
        except Exception:
            pass
        spf_record = []
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            for r in answers:
                txt = str(r).strip('"')
                if "v=spf" in txt.lower():
                    spf_record.append(txt)
        except Exception:
            pass
        return PluginResult(plugin_name=self.name, status="success", data={"received_headers": received, "originating_domain": domain, "mx_records": received, "spf": spf_record[0] if spf_record else "Not found", "dkim": "Check manually", "dmarc": "Check _dmarc." + domain})
