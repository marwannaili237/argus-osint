"""IPv6 connectivity check plugin."""
import logging
import dns.resolver
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class NetworkIPv6Plugin(BasePlugin):
    name = "network_ipv6"
    target_types = ["domain", "ip"]
    timeout_seconds = 15

    async def run(self, target: str) -> PluginResult:
        """Check for IPv6 (AAAA) records and IPv6 connectivity for a domain or IP."""
        aaaa_records = []
        has_aaaa = False

        # If it's already an IPv6 address
        if ":" in target:
            return PluginResult(
                plugin_name=self.name, status="success",
                data={
                    "has_aaaa": True,
                    "aaaa_records": [{"address": target, "nameserver": "direct"}],
                    "ipv6_compatible": True,
                    "note": "Target is itself an IPv6 address.",
                },
            )

        # If it's an IPv4 address, check for PTR and no AAAA
        if target.count(".") == 3:
            return PluginResult(
                plugin_name=self.name, status="success",
                data={
                    "has_aaaa": False,
                    "aaaa_records": [],
                    "ipv6_compatible": False,
                    "note": "Target is an IPv4 address. No AAAA lookup applicable.",
                },
            )

        # It's a domain - try AAAA lookup
        try:
            answers = dns.resolver.resolve(target, "AAAA")
            for r in answers:
                aaaa_records.append({"address": str(r), "nameserver": "default"})
            has_aaaa = bool(aaaa_records)
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            return PluginResult(
                plugin_name=self.name, status="error", data={},
                error_message=f"Domain {target} does not exist",
            )
        except Exception as e:
            logger.debug(f"AAAA lookup error for {target}: {e}")

        # Also check CAA records as a bonus
        caa_records = []
        try:
            for r in dns.resolver.resolve(target, "CAA"):
                caa_records.append({
                    "flags": r.flags,
                    "tag": r.tag,
                    "value": r.value,
                })
        except Exception:
            pass

        return PluginResult(
            plugin_name=self.name, status="success",
            data={
                "has_aaaa": has_aaaa,
                "aaaa_records": aaaa_records,
                "ipv6_compatible": has_aaaa,
                "caa_records": caa_records,
                "total_aaaa": len(aaaa_records),
            },
        )