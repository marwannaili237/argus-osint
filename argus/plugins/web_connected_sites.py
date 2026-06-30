"""Connected/related sites discovery plugin."""
import logging
import dns.resolver
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class WebConnectedSitesPlugin(BasePlugin):
    name = "web_connected_sites"
    target_types = ["domain"]
    timeout_seconds = 30

    async def run(self, target: str) -> PluginResult:
        """Find connected/related sites by checking shared infrastructure:
        same IP, same nameservers, same registrar patterns."""
        connected_sites = []
        same_ip_sites = []
        same_nameserver_sites = []
        ip_addresses = set()
        nameservers = set()

        # Resolve A records to get IP addresses
        try:
            answers = dns.resolver.resolve(target, "A")
            ip_addresses = {str(r) for r in answers}
        except Exception:
            pass

        # Get nameservers
        try:
            answers = dns.resolver.resolve(target, "NS")
            nameservers = {str(r.target).rstrip(".") for r in answers}
        except Exception:
            pass

        # Reverse DNS on the IPs to find other domains sharing them
        for ip in ip_addresses:
            try:
                answers = dns.resolver.resolve(dns.reversename.from_address(ip), "PTR")
                for r in answers:
                    ptr_domain = str(r).rstrip(".")
                    if ptr_domain != target:
                        same_ip_sites.append({
                            "domain": ptr_domain,
                            "shared_ip": ip,
                            "method": "reverse_dns",
                        })
            except Exception:
                pass

        # Check Certificate Transparency logs via crt.sh
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://crt.sh/?q=%.{target}&output=json",
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        certs = await resp.json()
                        seen = set()
                        for cert in certs:
                            name = cert.get("name_value", "")
                            for domain in name.split("\n"):
                                domain = domain.strip().lstrip("*.")
                                if domain and domain != target and domain not in seen:
                                    seen.add(domain)
                                    connected_sites.append({
                                        "domain": domain,
                                        "source": "certificate_transparency",
                                        "issuer": cert.get("issuer_name", "")[:100],
                                    })
        except Exception as e:
            logger.debug(f"crt.sh lookup failed: {e}")

        # Check if nameservers host other known domains (heuristic)
        for ns in nameservers:
            # Known shared hosting patterns
            shared_hosting_indicators = ["cloudflare", "google", "awsdns", "azure", "digitalocean", "linode", "vultr"]
            for indicator in shared_hosting_indicators:
                if indicator in ns.lower():
                    same_nameserver_sites.append({
                        "nameserver": ns,
                        "hosting_provider": indicator.title(),
                        "note": f"Uses {indicator} nameservers - shared hosting likely",
                    })

        # Deduplicate connected sites
        unique_connected = []
        seen_domains = set()
        for site in connected_sites:
            d = site["domain"]
            if d not in seen_domains:
                seen_domains.add(d)
                unique_connected.append(site)

        return PluginResult(
            plugin_name=self.name, status="success",
            data={
                "connected_sites": unique_connected[:50],
                "same_ip": same_ip_sites,
                "same_nameservers": list(same_nameserver_sites),
                "ip_addresses": list(ip_addresses),
                "nameservers": list(nameservers),
                "total_connected": len(unique_connected),
            },
        )
