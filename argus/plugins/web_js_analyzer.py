"""JavaScript file analyzer plugin - extracts endpoints, API keys, and sensitive data from JS files."""
import re
import logging
import aiohttp
from urllib.parse import urlparse, urljoin
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)

# Patterns for sensitive data in JS
API_KEY_PATTERNS = [
    re.compile(r'["\'](?:api[_-]?key|apikey|api[_-]?secret|token|access[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', re.IGNORECASE),
    re.compile(r'["\'](?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}["\']'),
    re.compile(r'["\'](sk[-_])?[A-Za-z0-9]{40,}["\']'),
    re.compile(r'firebase[_a-z]+["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{30,})["\']', re.IGNORECASE),
    re.compile(r'ghp_[A-Za-z0-9]{36,}'),
    re.compile(r'gho_[A-Za-z0-9]{36,}'),
]

ENDPOINT_PATTERNS = [
    re.compile(r'["\'](?:https?://[^"\' ]+(?:/api/|/v[0-9]+/|/rest/)[^"\' ]*)["\']'),
    re.compile(r'(?:fetch|axios|XMLHttpRequest)\s*\(\s*["\']([^"\' ]+)["\']'),
    re.compile(r'"(?:path|endpoint|url)":\s*"([^"]+)"', re.IGNORECASE),
]

SENSITIVE_PATTERNS = [
    re.compile(r'password\s*[:=]\s*["\']([^"\']{3,})["\']', re.IGNORECASE),
    re.compile(r'secret\s*[:=]\s*["\']([^"\']{3,})["\']', re.IGNORECASE),
    re.compile(r'credentials?\s*[:=]\s*["\']([^"\']{3,})["\']', re.IGNORECASE),
    re.compile(r'authorization["\']?\s*[:=]\s*["\'](?:Bearer |Basic )?(.+?)["\']', re.IGNORECASE),
]

JS_SRC_PATTERN = re.compile(r'src=["\']([^"\' ]+\.js[^"\' ]*)["\' ]', re.IGNORECASE)
MAX_JS_FILES = 20


class WebJsAnalyzerPlugin(BasePlugin):
    name = "web_js_analyzer"
    target_types = ["domain", "url"]
    timeout_seconds = 45

    async def run(self, target: str) -> PluginResult:
        """Fetch a page, find all JS files, and analyze them for sensitive data."""
        base_url = target if target.startswith("http") else f"https://{target}"

        # Fetch the main page to find JS files
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    base_url, timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False, allow_redirects=True,
                ) as resp:
                    if resp.status != 200:
                        return PluginResult(
                            plugin_name=self.name, status="error", data={},
                            error_message=f"Could not fetch page: HTTP {resp.status}",
                        )
                    html = await resp.text()

                # Extract JS file URLs
                js_urls = []
                for m in JS_SRC_PATTERN.finditer(html):
                    js_url = urljoin(base_url, m.group(1))
                    js_urls.append(js_url)
                js_urls = list(set(js_urls))[:MAX_JS_FILES]

                # Fetch and analyze each JS file
                js_files_info = []
                all_endpoints = set()
                all_api_keys = []
                all_sensitive = []

                for js_url in js_urls:
                    try:
                        async with session.get(
                            js_url, timeout=aiohttp.ClientTimeout(total=8),
                            ssl=False, allow_redirects=True,
                        ) as js_resp:
                            if js_resp.status != 200:
                                js_files_info.append({"url": js_url, "size": 0, "status": js_resp.status})
                                continue
                            js_content = await js_resp.text()
                            size = len(js_content)
                            is_minified = size > 500 and '\n' not in js_content[:500]

                            # Extract endpoints
                            for pat in ENDPOINT_PATTERNS:
                                for m in pat.finditer(js_content):
                                    all_endpoints.add(m.group(1))

                            # Extract API keys
                            for pat in API_KEY_PATTERNS:
                                for m in pat.finditer(js_content):
                                    key_val = m.group(1) if m.lastindex else m.group(0)
                                    if len(key_val) > 15:
                                        all_api_keys.append({"value": key_val[:50], "source": js_url})

                            # Extract sensitive data
                            for pat in SENSITIVE_PATTERNS:
                                for m in pat.finditer(js_content):
                                    val = m.group(1) if m.lastindex else m.group(0)
                                    if len(val) > 3:
                                        all_sensitive.append({"type": pat.pattern[:30], "value": val[:50], "source": js_url})

                            js_files_info.append({
                                "url": js_url, "size": size,
                                "minified": is_minified, "status": 200,
                            })
                    except Exception:
                        js_files_info.append({"url": js_url, "size": 0, "status": "error"})

                return PluginResult(
                    plugin_name=self.name, status="success",
                    data={
                        "js_files": js_files_info,
                        "total_js_files": len(js_urls),
                        "endpoints_found": sorted(all_endpoints)[:50],
                        "api_keys_found": all_api_keys[:20],
                        "sensitive_data": all_sensitive[:20],
                        "total_endpoints": len(all_endpoints),
                        "total_api_keys": len(all_api_keys),
                        "total_sensitive": len(all_sensitive),
                    },
                )
        except Exception as e:
            logger.error(f"JS analyzer failed: {e}")
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message=str(e))
