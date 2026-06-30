"""DNS zone transfer attempt plugin."""
import logging
import dns.resolver
import dns.zone
import dns.message
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class NetworkZoneTransferPlugin(BasePlugin):
    name = "network_zone_transfer"
    target_types = ["domain"]
    timeout_seconds = 30

    async def run(self, target: str) -> PluginResult:
        """Attempt DNS zone transfer (AXFR) against the domain's nameservers.
        Zone transfer is a common misconfiguration that exposes all DNS records."""
        nameservers = []
        records = []
        zone_transfer_possible = False

        # First, get the nameservers
        try:
            answers = dns.resolver.resolve(target, "NS")
            nameservers = [str(r.target).rstrip(".") for r in answers]
        except Exception as e:
            logger.warning(f"Could not resolve NS records for {target}: {e}")
            return PluginResult(
                plugin_name=self.name, status="success",
                data={
                    "zone_transfer_possible": False,
                    "records": [],
                    "nameservers": [],
                    "error": "Could not resolve nameservers",
                },
            )

        # Attempt AXFR against each nameserver
        for ns in nameservers:
            try:
                # Use dnspython's zone transfer function
                zone = dns.zone.from_xfr(dns.query.xfr(ns, target, lifetime=10))
                zone_transfer_possible = True
                for name, node in zone.items():
                    for rdataset in node:
                        for rdata in rdataset:
                            records.append({
                                "name": str(name),
                                "type": rdataset.rdtype.name,
                                "value": str(rdata),
                                "ttl": rdataset.ttl,
                                "nameserver": ns,
                            })
                break  # One successful transfer is enough
            except (dns.exception.FormError, dns.query.TransferError, ConnectionRefusedError, TimeoutError) as e:
                logger.debug(f"Zone transfer failed from {ns}: {e}")
            except Exception as e:
                logger.debug(f"Zone transfer error from {ns}: {e}")

        return PluginResult(
            plugin_name=self.name, status="success",
            data={
                "zone_transfer_possible": zone_transfer_possible,
                "records": records[:500],  # Cap at 500 records
                "nameservers": nameservers,
                "total_records": len(records),
                "risk_level": "CRITICAL" if zone_transfer_possible else "LOW",
            },
        )