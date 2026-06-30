"""CDN and WAF detection plugin."""
import logging
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)

# Known CDN/WAF header and IP signatures
CDN_SIGNATURES = {
    "cloudflare": {"headers": ["cf-ray", "cf-connecting-ip"], "server": "cloudflare"},
    "akamai": {"headers": ["x-akamai-staging", "x-akamai-transformed"], "server": "akamai"},
    "fastly": {"headers": ["x-fastly-request-id", "x-fastly-trace-id"], "server": "fastly"},
    "aws_cloudfront": {"headers": ["x-amz-cf-id"], "server": "cloudfront"},
    "azure_cdn": {"headers": ["x-azure-ref"], "server": "azurecdn"},
    "google_cloud": {"headers": ["x-goog-request-id"], "server": "gws"},
    "sucuri": {"headers": ["x-sucuri-id", "x-sucuri-cache"], "server": "sucuri"},
    "imperva": {"headers": ["x-iinfo"], "server": "incap_sucuri"},
    "varnish": {"headers": ["x-varnish"], "server": "varnish"},
    "cloudflare_waf": {"headers": ["cf-mitigated"], "server": "cloudflare"},
}

WAF_SIGNATURES = {
    "cloudflare_waf": ["cf-mitigated", "__cfduid"],
    "aws_waf": ["awselb", "x-amzn-requestid"],
    "akamai_waf": ["akamai_glb", "x-akamai-geo"],
    "sucuri_waf": ["x-sucuri-id"],
    "imperva_waf": ["x-iinfo", "x-cdn"],
    "modsecurity": ["mod_security", "modsecurity"],
}


class NetworkCdnWafPlugin(BasePlugin):
    name = "network_cdn_waf"
    target_types = ["domain", "url"]
    timeout_seconds = 15

    async def run(self, target: str) -> PluginResult:
        """Detect CDN and WAF presence by inspecting HTTP headers and server responses."""
        url = target if target.startswith("http") else f"https://{target}"
        headers_found = {}
        cdn_detected = False
        cdn_provider = None
        waf_detected = False
        waf_provider = None
        server_value = ""

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=True,
                    ssl=False,
                ) as resp:
                    # Collect all response headers (lowercase)
                    for key, value in resp.headers.items():
                        headers_found[key.lower()] = value

                    server_value = resp.headers.get("Server", "").lower()

                    # Check for CDN signatures
                    for cdn_name, sigs in CDN_SIGNATURES.items():
                        matched_header = None
                        for hdr in sigs.get("headers", []):
                            if hdr.lower() in headers_found:
                                matched_header = hdr
                                break
                        if sigs.get("server") and sigs["server"] in server_value:
                            matched_header = f"Server: {server_value}"
                        if matched_header:
                            cdn_detected = True
                            cdn_provider = cdn_name.replace("_", " ").title()
                            break

                    # Check for WAF signatures
                    for waf_name, sig_headers in WAF_SIGNATURES.items():
                        for hdr in sig_headers:
                            if hdr.lower() in headers_found:
                                waf_detected = True
                                waf_provider = waf_name.replace("_", " ").title()
                                break
                        if waf_detected:
                            break

                    # Additional WAF heuristics
                    if resp.status == 403 and ("denied" in (await self._safe_read(resp))[:500].lower() or
                                               "forbidden" in (await self._safe_read(resp))[:500].lower()):
                        if not waf_detected:
                            waf_detected = True
                            waf_provider = "Unknown WAF (403 detected)"

        except Exception as e:
            logger.error(f"CDN/WAF detection failed: {e}")
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message=str(e))

        return PluginResult(
            plugin_name=self.name, status="success",
            data={
                "cdn_detected": cdn_detected,
                "cdn_provider": cdn_provider,
                "waf_detected": waf_detected,
                "waf_provider": waf_provider,
                "headers": {k: v for k, v in headers_found.items() if k.startswith("x-") or k == "server"},
                "server": server_value,
            },
        )

    async def _safe_read(self, resp: aiohttp.ClientResponse, limit: int = 1000) -> str:
        """Safely read response body without consuming the stream for later use."""
        try:
            chunk = await resp.content.read(limit)
            return chunk.decode("utf-8", errors="replace")
        except Exception:
            return ""