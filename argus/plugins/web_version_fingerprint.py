"""Web technology version fingerprinting plugin."""
import re
import logging
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)

# Technology detection patterns from HTTP headers and page content
HEADER_TECH = {
    "X-Powered-By": lambda v: v,
    "Server": lambda v: v,
    "X-AspNet-Version": lambda v: f"ASP.NET {v}",
    "X-Drupal-Cache": lambda v: "Drupal",
    "X-Generator": lambda v: f"Generator: {v}",
    "X-WordPress-Flow": lambda v: "WordPress",
}

BODY_TECH_PATTERNS = [
    ("WordPress", [r'<meta\s+name="generator"\s+content="WordPress\s+([\d.]+)"', r'wp-content', r'wp-includes']),
    ("Drupal", [r'<meta\s+name="Generator"\s+content="Drupal\s+([\d.]+)"', r'Drupal.settings', r'/sites/all/']),
    ("Joomla", [r'<meta\s+name="generator"\s+content="Joomla!', r'/media/jui/']),
    ("React", [r'__NEXT_DATA__', r'react', r'_reactRoot', r'data-reactroot']),
    ("Vue.js", [r'vue\.js', r'v-cloak', r'__VUE_APP__']),
    ("Angular", [r'ng-version="([^"]+)"', r'ng-app', r'angular']),
    ("jQuery", [r'jquery[\.-]', r'jQuery\.fn']),
    ("Bootstrap", [r'bootstrap[\.\-/]', r'bootstrap\.min\.css']),
    ("Tailwind CSS", [r'tailwind', r'tw-']),
    ("Laravel", [r'laravel_session', r'laravel_token']),
    ("Django", [r'csrfmiddlewaretoken']),
    ("Flask", [r'flask']),
    ("Next.js", [r'__NEXT_DATA__', r'_next/static']),
    ("Nuxt.js", [r'__NUXT__', r'_nuxt/']),
    ("Shopify", [r'Shopify\.theme', r'storefront/', r'shopify']),
    ("WooCommerce", [r'woocommerce', r'WooCommerce']),
    ("phpMyAdmin", [r'phpMyAdmin', r'pma_']),
    ("cPanel", [r'cPanel', r'x3.cpanel']),
    ("Cloudflare Pages", [r'cloudflare', r'__CF']),
    ("Vercel", [r'vercel', r'x-vercel-id']),
    ("Netlify", [r'netlify', r'x-nf-request-id']),
    ("Google Analytics", [r'google-analytics\.com', r'gtag\(', r'GA_']),
    ("Google Tag Manager", [r'googletagmanager\.com', r'GTM-']),
    ("Cloudflare", [r'cf-browser-verification', r'_cf_chl']),
]

import re as _re


class WebVersionFingerprintPlugin(BasePlugin):
    name = "web_version_fingerprint"
    target_types = ["domain", "url"]
    timeout_seconds = 20

    async def run(self, target: str) -> PluginResult:
        """Detect web technologies and their versions from HTTP headers and page content."""
        base_url = target if target.startswith("http") else f"https://{target}"
        technologies = []
        meta_generator = ""
        powered_by = ""

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    base_url, timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False, allow_redirects=True,
                ) as resp:
                    headers = dict(resp.headers)
                    body = await resp.text()
                    lower_body = body.lower()

                    # Check header-based technologies
                    for header_name, extractor in HEADER_TECH.items():
                        value = headers.get(header_name, "")
                        if value:
                            tech_name = extractor(value)
                            technologies.append({
                                "name": tech_name,
                                "version": "",
                                "category": "header",
                                "source": header_name,
                            })
                            if header_name == "X-Powered-By":
                                powered_by = value
                            if header_name == "X-Generator":
                                meta_generator = value

                    # Check meta generator tag
                    if not meta_generator:
                        gen_m = _re.search(
                            r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\'>]+)["\' ]',
                            body, _re.IGNORECASE,
                        )
                        if gen_m:
                            meta_generator = gen_m.group(1)
                            technologies.append({
                                "name": meta_generator.strip(),
                                "version": "",
                                "category": "meta",
                                "source": "generator meta tag",
                            })

                    # Check body-based technology patterns
                    for tech_name, patterns in BODY_TECH_PATTERNS:
                        for pattern in patterns:
                            m = _re.search(pattern, body, _re.IGNORECASE)
                            if m:
                                version = ""
                                if m.lastindex and m.lastindex >= 1:
                                    version = m.group(1) if m.group(1).isdigit() or '.' in str(m.group(1)) else ""
                                technologies.append({
                                    "name": tech_name,
                                    "version": version,
                                    "category": "content",
                                    "source": pattern[:50],
                                })
                                break  # Found this tech, no need to check more patterns

                    # Deduplicate by name
                    seen = set()
                    unique_tech = []
                    for t in technologies:
                        key = t["name"].lower()
                        if key not in seen:
                            seen.add(key)
                            unique_tech.append(t)

                    return PluginResult(
                        plugin_name=self.name, status="success",
                        data={
                            "technologies": unique_tech,
                            "total_technologies": len(unique_tech),
                            "meta_generator": meta_generator,
                            "powered_by": powered_by,
                            "server": headers.get("Server", ""),
                            "url": base_url,
                        },
                    )
        except Exception as e:
            logger.error(f"Version fingerprint failed: {e}")
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message=str(e))