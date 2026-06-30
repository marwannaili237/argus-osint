"""Reverse image search plugin."""
import logging
import hashlib
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class ReverseImagePlugin(BasePlugin):
    name = "reverse_image"
    target_types = ["image"]
    timeout_seconds = 30

    async def run(self, target: str) -> PluginResult:
        """Perform reverse image search by computing perceptual hash and
        checking against search engines."""
        image_hash = ""
        image_size = 0
        content_type = ""
        search_urls = {}
        similar_images = []
        exact_matches = []

        # Download the image
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    target, timeout=aiohttp.ClientTimeout(total=15),
                    ssl=False, allow_redirects=True,
                ) as resp:
                    if resp.status != 200:
                        return PluginResult(
                            plugin_name=self.name, status="error", data={},
                            error_message=f"Could not fetch image: HTTP {resp.status}",
                        )
                    content = await resp.read()
                    image_size = len(content)
                    content_type = resp.headers.get("Content-Type", "unknown")
                    image_hash = hashlib.md5(content).hexdigest()
                    sha256_hash = hashlib.sha256(content).hexdigest()

                    # Compute average hash (aHash) for similarity
                    try:
                        from PIL import Image
                        import io
                        img = Image.open(io.BytesIO(content)).convert('L').resize((8, 8), Image.LANCZOS)
                        pixels = list(img.getdata())
                        avg = sum(pixels) / len(pixels)
                        ahash = ''.join(['1' if p >= avg else '0' for p in pixels])
                    except ImportError:
                        ahash = ""

                    # Build reverse search URLs
                    encoded_url = target.replace(":", "%3A").replace("/", "%2F")
                    search_urls = {
                        "google_images": f"https://lens.google.com/uploadbyurl?url={target}",
                        "tineye": f"https://tineye.com/search/?url={target}",
                        "yandex": f"https://yandex.com/images/search?rpt=imageview&url={target}",
                        "bing_visual": f"https://www.bing.com/visualsearch?imgurl={target}",
                    }

                    # Try Google Images (via simple fetch, not full API)
                    try:
                        google_url = f"https://lens.google.com/uploadbyurl?url={target}"
                        async with session.get(
                            google_url, timeout=aiohttp.ClientTimeout(total=5),
                            allow_redirects=True,
                        ) as gresp:
                            if gresp.status == 200:
                                gtext = await gresp.text()
                                import re
                                # Try to extract some useful info
                                if 'similar' in gtext.lower() or 'match' in gtext.lower():
                                    similar_images.append({"source": "google_lens", "url": google_url})
                    except Exception:
                        pass

        except Exception as e:
            logger.error(f"Reverse image search failed: {e}")
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message=str(e))

        return PluginResult(
            plugin_name=self.name, status="success",
            data={
                "image_url": target,
                "md5_hash": image_hash,
                "sha256_hash": sha256_hash if 'sha256_hash' in dir() else "",
                "perceptual_hash": ahash if 'ahash' in dir() else "",
                "size_bytes": image_size,
                "content_type": content_type,
                "reverse_search_urls": search_urls,
                "similar_images": similar_images,
                "exact_matches": exact_matches,
                "has_exif": False,
            },
        )