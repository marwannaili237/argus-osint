"""Network traceroute plugin using async subprocess."""
import asyncio
import logging
import re
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class NetworkTraceroutePlugin(BasePlugin):
    name = "network_traceroute"
    target_types = ["ip", "domain"]
    timeout_seconds = 45

    async def run(self, target: str) -> PluginResult:
        """Perform a traceroute to the target using system traceroute command."""
        hops = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "traceroute", "-n", "-w", "2", "-q", "1", "-m", "20", target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=40)
            output = stdout.decode("utf-8", errors="replace")

            for line in output.strip().splitlines():
                line = line.strip()
                if not line or line.startswith("traceroute"):
                    continue
                parts = re.split(r'\s+', line)
                if not parts:
                    continue
                try:
                    hop_num = int(parts[0])
                except ValueError:
                    continue

                ip_addr = "*"
                rtt_ms = None
                hostname = ""

                # Parse: hop_num hostname (ip) rtt_ms  or  hop_num ip rtt_ms
                for p in parts[1:]:
                    # Look for IP address pattern
                    ip_match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', p)
                    if ip_match:
                        ip_addr = ip_match.group(1)
                    # Look for RTT in ms
                    rtt_match = re.match(r'^([\d.]+)\s*ms$', p)
                    if rtt_match:
                        rtt_ms = float(rtt_match.group(1))
                    # Look for hostname (not IP, not ms)
                    if not ip_match and not rtt_match and not p.startswith('*') and not p == '':
                        hostname = p

                hops.append({
                    "hop": hop_num,
                    "ip": ip_addr,
                    "hostname": hostname,
                    "rtt_ms": rtt_ms,
                })

            destination_reached = any(h["ip"] != "*" for h in hops[-3:]) if hops else False

        except FileNotFoundError:
            # traceroute not installed, provide mock data
            return PluginResult(
                plugin_name=self.name, status="error", data={},
                error_message="traceroute command not found. Install iputils-traceroute.",
            )
        except asyncio.TimeoutError:
            return PluginResult(
                plugin_name=self.name, status="timeout", data={"hops": hops, "timeout": True},
                error_message="Traceroute timed out",
            )
        except Exception as e:
            logger.error(f"Traceroute failed: {e}")
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message=str(e))

        return PluginResult(
            plugin_name=self.name, status="success",
            data={
                "hops": hops,
                "total_hops": len(hops),
                "destination_reached": destination_reached,
                "target": target,
            },
        )