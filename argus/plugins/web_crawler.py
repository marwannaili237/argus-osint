"""Web crawler plugin - crawls pages and extracts links, forms, technologies, and emails."""
import re
import logging
import aiohttp
from urllib.parse import urljoin, urlparse, urlunparse
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)

# Patterns for data extraction
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
PHONE_PATTERN = re.compile(r'\+?\d[\d\s-]{8,15}\d')
FORM_ACTION_PATTERN = re.compile(r'<form[^>]*action=["\'](https?://[^"\' ]+)["\' ]', re.IGNORECASE)
LINK_PATTERN = re.compile(r'href=["\'](https?://[^"\' ]+)["\' ]', re.IGNORECASE)
JS_FILE_PATTERN = re.compile(r'src=["\'](https?://[^"\' ]+\.js[^"\' ]*)["\' ]', re.IGNORECASE)
META_GEN_PATTERN = re.compile(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\'>]+)["\' ]', re.IGNORECASE)

# Technology detection keywords in HTML/headers
TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "wordpress"],
    "Drupal": ["Drupal", "drupal.js", "sites/default"],
    "Joomla": ["/media/jui/", "Joomla!", "components/com_"],
    "React": ["react", "__NEXT_DATA__", "_reactRoot"],
    "Vue.js": ["vue.js", "v-cloak", "v-bind", "__vue_app__"],
    "Angular": ["ng-version", "angular", "ng-app"],
    "jQuery": ["jquery", "jQuery"],
    "Bootstrap": ["bootstrap", "bootstrap.min.css"],
    "Tailwind CSS": ["tailwind", "tw-"],
    "Laravel": ["laravel", "laravel_session"],
    "Django": ["csrfmiddlewaretoken", "django"],
    "Flask": ["flask", "werkzeug"],
    "Express": ["x-powered-by: express"],
    "Next.js": ["__NEXT_DATA__", "_next/static"],
    "Nuxt.js": ["__NUXT__", "_nuxt/"],
}

MAX_PAGES = 10
MAX_LINKS = 200


class WebCrawlerPlugin(BasePlugin):
    name = "web_crawler"
    target_types = ["domain", "url"]
    timeout_seconds = 60

    async def run(self, target: str) -> PluginResult:
        """Crawl a website and extract links, forms, technologies, emails, and phone numbers."""
        base_url = target if target.startswith("http") else f"https://{target}"
        parsed = urlparse(base_url)
        base_domain = parsed.netloc

        pages_crawled = 0
        all_links = []
        all_forms = []
        all_emails = set()
        all_phones = set()
        technologies = set()
        js_files = []
        visited = set()
        to_visit = {base_url}

        try:
            async with aiohttp.ClientSession() as session:
                while to_visit and pages_crawled < MAX_PAGES:
                    url = to_visit.pop()
                    if url in visited:
                        continue
                    visited.add(url)

                    try:
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=8),
                            ssl=False,
                            allow_redirects=True,
                        ) as resp:
                            if resp.status != 200:
                                continue
                            content_type = resp.headers.get("Content-Type", "")
                            if "text/html" not in content_type:
                                continue
                            body = await resp.text()
                            pages_crawled += 1

                            # Extract links
                            for m in LINK_PATTERN.finditer(body):
                                link = m.group(1)
                                parsed_link = urlparse(link)
                                if parsed_link.netloc == base_domain and link not in visited:
                                    to_visit.add(link)
                                if len(all_links) < MAX_LINKS:
                                    all_links.append(link)

                            # Extract forms
                            for m in FORM_ACTION_PATTERN.finditer(body):
                                if len(all_forms) < 50:
                                    all_forms.append(urljoin(url, m.group(1)))

                            # Extract emails
                            for m in EMAIL_PATTERN.finditer(body):
                                all_emails.add(m.group(0))

                            # Extract phones
                            for m in PHONE_PATTERN.finditer(body):
                                phone = m.group(0).strip()
                                if len(phone) >= 10:
                                    all_phones.add(phone)

                            # Extract JS files
                            for m in JS_FILE_PATTERN.finditer(body):
                                if len(js_files) < 50:
                                    js_files.append(urljoin(url, m.group(1)))

                            # Detect technologies
                            lower_body = body.lower()
                            for tech, keywords in TECH_SIGNATURES.items():
                                for kw in keywords:
                                    if kw.lower() in lower_body:
                                        technologies.add(tech)
                                        break

                            # Check meta generator
                            gen_m = META_GEN_PATTERN.search(body)
                            if gen_m:
                                technologies.add(f"Generator: {gen_m.group(1).strip()}")

                            # Check server header
                            server = resp.headers.get("Server", "")
                            if server:
                                technologies.add(f"Server: {server}")

                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        continue

        except Exception as e:
            logger.error(f"Web crawler error: {e}")
            return PluginResult(
                plugin_name=self.name, status="error", data={},
                error_message=str(e),
            )

        return PluginResult(
            plugin_name=self.name, status="success",
            data={
                "pages_crawled": pages_crawled,
                "links": list(set(all_links))[:MAX_LINKS],
                "forms": list(set(all_forms)),
                "technologies": sorted(technologies),
                "emails_found": sorted(all_emails),
                "phones_found": sorted(all_phones),
                "js_files": js_files[:30],
                "total_links": len(set(all_links)),
                "total_emails": len(all_emails),
                "total_phones": len(all_phones),
            },
        )

import asyncio
