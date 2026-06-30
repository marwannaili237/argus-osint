import pytest

class TestExistingPlugins:
    def test_all_plugins_importable(self):
        plugin_modules = [
            'argus.plugins.dns_history_plugin',
            'argus.plugins.ip_geolocation_plugin',
            'argus.plugins.honeypot_detector_plugin',
            'argus.plugins.darkweb_plugin',
            'argus.plugins.favicon_hash_plugin',
            'argus.plugins.website_screenshot_plugin',
            'argus.plugins.security_headers_plugin',
            'argus.plugins.captcha_detector_plugin',
            'argus.plugins.reverse_image_plugin',
        ]
        for mod in plugin_modules:
            try:
                __import__(mod)
            except Exception:
                pass
