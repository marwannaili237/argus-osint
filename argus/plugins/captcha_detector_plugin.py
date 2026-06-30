"""CAPTCHA detection plugin."""
import re
import logging
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)

CAPTCHA_SIGNATURES = {
    "reCAPTCHA v2": {
        "patterns": [
            r'google\.com/recaptcha',
            r'g-recaptcha',
            r'data-sitekey="([^"]+)"',
            r'recaptcha/api\.js',
        ],
        "domain": "google.com",
    },
    "reCAPTCHA v3": {
        "patterns": [
            r'google\.com/recaptcha/api/js/recaptcha',
            r'grecaptcha\.execute',
            r'render=["\']explicit["\']',
        ],
        "domain": "google.com",
    },
    "hCaptcha": {
        "patterns": [
            r'hcaptcha\.com',
            r'h-captcha',
            r'data-hcaptcha-sitekey="([^"]+)"',
            r'hcaptcha\.com/1/api\.js',
        ],
        "domain": "hcaptcha.com",
    },
    "Cloudflare Turnstile": {
        "patterns": [
            r'challenges\.cloudflare\.com/turnstile',
            r'cf-turnstile',
            r'data-sitekey="([^"]+)"',  # Also used by Turnstile
            r'cloudflareturnstile',
        ],
        "domain": "cloudflare.com",
    },
    "Cloudflare Challenge": {
        "patterns": [
            r'cf-browser-verification',
            r'cf_chl_seq',
            r'challenge-platform',
            r'_cf_chl_tk',
        ],
        "domain": "cloudflare.com",
    },
    "Akamai Bot Manager": {
        "patterns": [
            r'akamai',
            r'_abck=',
            r'akamaized\.net',
            r'ak_bmsc',
        ],
        "domain": "akamai.com",
    },
    "DataDome": {
        "patterns": [
            r'datadome\.co',
            r'dd-cookie-consent',
            r'datadome',
        ],
        "domain": "datadome.co",
    },
    "PerimeterX": {
        "patterns": [
            r'perimeterx',
            r'_px',
            r'px-cdn\.net',
        ],
        "domain": "perimeterx.com",
    },
}


class CaptchaDetectorPlugin(BasePlugin):
    name = "captcha_detector"
    target_types = ["domain", "url"]
    timeout_seconds = 15

    async def run(self, target: str) -> PluginResult:
        """Detect CAPTCHA implementations on a webpage."""
        url = target if target.startswith("http") else f"https://{target}"
        captcha_types = []
        site_keys = []
        captcha_domains = set()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False, allow_redirects=True,
                ) as resp:
                    body = await resp.text()
                    headers_text = str(resp.headers)

                    # Check for each captcha type
                    for captcha_name, config in CAPTCHA_SIGNATURES.items():
                        for pattern in config["patterns"]:
                            matches = re.findall(pattern, body, re.IGNORECASE)
                            if matches:
                                captcha_types.append(captcha_name)
                                captcha_domains.add(config["domain"])
                                # Extract site keys if available
                                if isinstance(matches[0], str) and len(matches[0]) > 10 and matches[0].startswith(('6L', '0x')):
                                    site_keys.append({"type": captcha_name, "key": matches[0]})
                                break

                    # Also check response for captcha-like behavior
                    # (403 with challenge page)
                    if resp.status == 403:
                        if any(kw in body.lower() for kw in ["challenge", "verify", "robot", "human"]):
                            captcha_types.append("Unknown Challenge Page")

                    return PluginResult(
                        plugin_name=self.name, status="success",
                        data={
                            "has_captcha": len(captcha_types) > 0,
                            "captcha_types": list(set(captcha_types)),
                            "site_keys": site_keys,
                            "captcha_domains": list(captcha_domains),
                            "total_types": len(set(captcha_types)),
                        },
                    )
        except Exception as e:
            logger.error(f"CAPTCHA detection failed: {e}")
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message=str(e))