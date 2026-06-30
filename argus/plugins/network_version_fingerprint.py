"""Service version fingerprinting plugin via banner grabbing."""
import asyncio
import logging
import re
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)

# Common ports to check for banners
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]

# Known service patterns
SERVICE_PATTERNS = {
    21: [("FTP", [r"FTP", r"vsftpd", r"ProFTPD", r"Pure-FTPd", r"FileZilla"])],
    22: [("SSH", [r"SSH-[\d.]+", r"OpenSSH", r"dropbear"])],
    25: [("SMTP", [r"ESMTP", r"Postfix", r"Exim", r"Sendmail", r"Microsoft ESMTP"])],
    80: [("HTTP", [r"Apache", r"nginx", r"LiteSpeed", r"Microsoft-IIS"])],
    110: [("POP3", [r"POP3", r"Dovecot", r"Courier"])],
    143: [("IMAP", [r"IMAP", r"Dovecot", r"Courier"])],
    443: [("HTTPS", [r"Apache", r"nginx", r"LiteSpeed"])],
    3306: [("MySQL", [r"mysql", r"MariaDB"])],
    5432: [("PostgreSQL", [r"PostgreSQL"])],
    6379: [("Redis", [r"redis"])],
    8080: [("HTTP-Alt", [r"Apache", r"nginx", r"Jetty", r"Tomcat"])],
    9200: [("Elasticsearch", [r"Elasticsearch", r"Kibana"])],
    27017: [("MongoDB", [r"MongoDB"])],
}


class NetworkVersionFingerprintPlugin(BasePlugin):
    name = "network_version_fingerprint"
    target_types = ["ip", "domain"]
    timeout_seconds = 60

    async def run(self, target: str) -> PluginResult:
        """Attempt banner grabbing on common ports to identify running services and versions."""
        services = []
        tasks = []

        # Use HTTP-based detection for web ports
        web_ports = {80, 443, 8080, 8443}
        if target.startswith("http"):
            # Extract host from URL
            from urllib.parse import urlparse
            parsed = urlparse(target)
            host = parsed.hostname or target
        else:
            host = target

        # Check HTTP headers on common web ports
        for port in web_ports:
            tasks.append(self._check_http_banner(host, port))

        # Do raw socket banner grabs on non-web ports (limited set for speed)
        raw_ports = [21, 22, 25, 110, 143, 3306, 5432, 6379, 9200, 27017]
        for port in raw_ports:
            tasks.append(self._grab_banner(host, port))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, dict) and r.get("port"):
                services.append(r)

        # Try to guess OS based on service combinations
        os_guess = self._guess_os(services)

        return PluginResult(
            plugin_name=self.name, status="success",
            data={
                "services": services,
                "os_guess": os_guess,
                "ports_scanned": len(tasks),
                "services_found": len(services),
            },
        )

    async def _check_http_banner(self, host: str, port: int) -> dict:
        """Check HTTP server banner via headers."""
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{host}:{port}/"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=5),
                    ssl=False, allow_redirects=False,
                ) as resp:
                    server = resp.headers.get("Server", "")
                    powered_by = resp.headers.get("X-Powered-By", "")
                    return {
                        "port": port,
                        "service": "HTTP" if port != 443 else "HTTPS",
                        "version": server or "Unknown",
                        "banner": server,
                        "x_powered_by": powered_by,
                    }
        except Exception:
            return {}

    async def _grab_banner(self, host: str, port: int) -> dict:
        """Attempt to grab a raw TCP banner from a port."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3,
            )
            # Wait a moment for the server to send a banner
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=3)
                banner = data.decode("utf-8", errors="replace").strip()
            except asyncio.TimeoutError:
                banner = ""
            writer.close()
            await writer.wait_closed()

            if banner:
                # Try to identify the service
                service = "unknown"
                version = ""
                patterns = SERVICE_PATTERNS.get(port, [])
                for svc_name, pattern_list in patterns:
                    for pattern in pattern_list:
                        m = re.search(pattern, banner, re.IGNORECASE)
                        if m:
                            service = svc_name
                            version = banner[:200]
                            break
                return {"port": port, "service": service, "version": version, "banner": banner[:200]}
        except Exception:
            pass
        return {}

    def _guess_os(self, services: list) -> str:
        """Guess the operating system based on detected services."""
        service_names = {s.get("service", "").lower() for s in services}
        server_headers = {s.get("banner", "").lower() for s in services}
        if "winrm" in service_names or any("microsoft" in s for s in server_headers):
            return "Windows"
        if any("ubuntu" in s or "debian" in s for s in server_headers):
            return "Linux (Debian/Ubuntu)"
        if any("centos" in s or "rhel" in s or "red hat" in s for s in server_headers):
            return "Linux (RHEL/CentOS)"
        if any("openssh" in s for s in server_headers):
            return "Linux/Unix (likely)"
        return "Unknown"