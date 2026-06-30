"""Security headers audit plugin."""
import logging
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "recommended": ["DENY", "SAMEORIGIN"],
        "weight": 15,
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "recommended": ["nosniff"],
        "weight": 10,
    },
    "X-XSS-Protection": {
        "description": "Enables browser XSS filter",
        "recommended": ["1; mode=block"],
        "weight": 5,
    },
    "Content-Security-Policy": {
        "description": "Controls resource loading",
        "recommended": ["default-src"],  # Just needs to exist
        "weight": 25,
    },
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections",
        "recommended": ["max-age="],
        "weight": 20,
    },
    "Referrer-Policy": {
        "description": "Controls referrer information",
        "recommended": ["strict-origin-when-cross-origin", "no-referrer", "same-origin"],
        "weight": 5,
    },
    "Permissions-Policy": {
        "description": "Controls browser features",
        "recommended": ["camera", "geolocation"],
        "weight": 10,
    },
    "X-Permitted-Cross-Domain-Policies": {
        "description": "Controls cross-domain policy files",
        "recommended": ["none"],
        "weight": 5,
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Isolates browsing context",
        "recommended": ["same-origin"],
        "weight": 5,
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Controls cross-origin resource sharing",
        "recommended": ["same-origin", "same-site"],
        "weight": 5,
    },
}


class SecurityHeadersPlugin(BasePlugin):
    name = "security_headers"
    target_types = ["domain", "url"]
    timeout_seconds = 15

    async def run(self, target: str) -> PluginResult:
        """Audit HTTP security headers and compute a security grade."""
        url = target if target.startswith("http") else f"https://{target}"
        headers_found = {}
        headers_missing = []
        total_weight = 0
        max_weight = sum(h["weight"] for h in SECURITY_HEADERS.values())
        header_details = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False, allow_redirects=True,
                ) as resp:
                    all_headers = dict(resp.headers)

                    for header_name, config in SECURITY_HEADERS.items():
                        value = all_headers.get(header_name)
                        if value:
                            headers_found[header_name] = value
                            # Check if value matches recommended
                            is_recommended = any(
                                rec.lower() in value.lower() for rec in config["recommended"]
                            )
                            score = config["weight"] if is_recommended else config["weight"] // 2
                            total_weight += score
                            header_details.append({
                                "name": header_name,
                                "value": value,
                                "status": "OK" if is_recommended else "WEAK",
                                "description": config["description"],
                            })
                        else:
                            headers_missing.append({
                                "name": header_name,
                                "description": config["description"],
                                "weight": config["weight"],
                            })
                            header_details.append({
                                "name": header_name,
                                "value": None,
                                "status": "MISSING",
                                "description": config["description"],
                            })

                    # Calculate score and grade
                    score_pct = round((total_weight / max_weight) * 100) if max_weight > 0 else 0

                    if score_pct >= 90:
                        grade = "A"
                    elif score_pct >= 80:
                        grade = "B"
                    elif score_pct >= 65:
                        grade = "C"
                    elif score_pct >= 50:
                        grade = "D"
                    else:
                        grade = "F"

                    return PluginResult(
                        plugin_name=self.name, status="success",
                        data={
                            "headers_found": headers_found,
                            "headers_missing": [h["name"] for h in headers_missing],
                            "missing_details": headers_missing,
                            "score": score_pct,
                            "grade": grade,
                            "header_details": header_details,
                            "total_headers_checked": len(SECURITY_HEADERS),
                            "headers_present": len(headers_found),
                        },
                    )
        except Exception as e:
            logger.error(f"Security headers check failed: {e}")
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message=str(e))