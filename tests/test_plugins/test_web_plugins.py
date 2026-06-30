import pytest
class TestWebPlugins:
    def test_crawler(self):
        from argus.plugins.web_crawler import WebCrawlerPlugin
        assert WebCrawlerPlugin().name == "web_crawler"
    def test_archive(self):
        from argus.plugins.web_archive import WebArchivePlugin
        assert WebArchivePlugin().name == "web_archive"
    def test_broken_links(self):
        from argus.plugins.web_broken_links import WebBrokenLinksPlugin
        assert WebBrokenLinksPlugin().name == "web_broken_links"
    def test_js_analyzer(self):
        from argus.plugins.web_js_analyzer import WebJsAnalyzerPlugin, API_KEY_PATTERNS
        assert len(API_KEY_PATTERNS) >= 3
    def test_doc_metadata(self):
        from argus.plugins.web_doc_metadata import WebDocMetadataPlugin
        assert WebDocMetadataPlugin().name == "web_doc_metadata"
    def test_connected_sites(self):
        from argus.plugins.web_connected_sites import WebConnectedSitesPlugin
        assert WebConnectedSitesPlugin().name == "web_connected_sites"
    def test_version_fp(self):
        from argus.plugins.web_version_fingerprint import WebVersionFingerprintPlugin, BODY_TECH_PATTERNS
        assert len(BODY_TECH_PATTERNS) >= 10
    def test_security_headers(self):
        from argus.plugins.security_headers_plugin import SecurityHeadersPlugin, SECURITY_HEADERS
        assert len(SECURITY_HEADERS) >= 8
    def test_captcha(self):
        from argus.plugins.captcha_detector_plugin import CaptchaDetectorPlugin, CAPTCHA_SIGNATURES
        assert len(CAPTCHA_SIGNATURES) >= 5
    def test_reverse_image(self):
        from argus.plugins.reverse_image_plugin import ReverseImagePlugin
        assert ReverseImagePlugin().name == "reverse_image"
