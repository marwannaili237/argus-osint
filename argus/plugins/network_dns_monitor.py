"""DNS consistency monitor plugin - checks across multiple resolvers."""
import asyncio
import logging
import dns.resolver
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)

# Public DNS resolvers to cross-check
RESOLVERS = [
    ("Google", "8.8.8.8"),
    ("Cloudflare", "1.1.1.1"),
    ("Quad9", "9.9.9.9"),
    ("OpenDNS", "208.67.222.222"),
]

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


class NetworkDnsMonitorPlugin(BasePlugin):
    name = "network_dns_monitor"
    target_types = ["domain"]
    timeout_seconds = 30

    async def run(self, target: str) -> PluginResult:
        """Check DNS record consistency across multiple public resolvers.
        Discrepancies can indicate DNS poisoning, misconfiguration, or hijacking."""
        resolver_results = {}
        all_discrepancies = []

        for resolver_name, resolver_ip in RESOLVERS:
            resolver_results[resolver_name] = {}
            for rtype in RECORD_TYPES:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [resolver_ip]
                    resolver.timeout = 5
                    resolver.lifetime = 5
                    answers = resolver.resolve(target, rtype)
                    values = sorted([str(r) for r in answers])
                    resolver_results[resolver_name][rtype] = values
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception) as e:
                    resolver_results[resolver_name][rtype] = None

        # Compare results across resolvers
        consistency = True
        first_resolver = RESOLVERS[0][0]
        for rtype in RECORD_TYPES:
            reference = resolver_results.get(first_resolver, {}).get(rtype)
            for rname, _ in RESOLVERS[1:]:
                current = resolver_results.get(rname, {}).get(rtype)
                if reference != current:
                    consistency = False
                    all_discrepancies.append({
                        "record_type": rtype,
                        f"{first_resolver}_value": reference,
                        f"{rname}_value": current,
                    })

        return PluginResult(
            plugin_name=self.name, status="success",
            data={
                "records": resolver_results,
                "consistency": consistency,
                "resolver_discrepancies": all_discrepancies,
                "resolvers_checked": [r[0] for r in RESOLVERS],
                "risk_level": "HIGH" if not consistency else "LOW",
            },
        )