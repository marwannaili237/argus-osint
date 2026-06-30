import pytest
class TestClassifier:
    def test_domain(self):
        from argus.plugins.classifier import classify_target
        assert classify_target("example.com") == "domain"
    def test_subdomain(self):
        from argus.plugins.classifier import classify_target
        assert classify_target("www.example.com") == "domain"
    def test_ip(self):
        from argus.plugins.classifier import classify_target
        assert classify_target("192.168.1.1") == "ip"
    def test_email(self):
        from argus.plugins.classifier import classify_target
        assert classify_target("user@example.com") == "email"
    def test_url(self):
        from argus.plugins.classifier import classify_target
        assert classify_target("https://example.com") == "url"
    def test_username(self):
        from argus.plugins.classifier import classify_target
        assert classify_target("john_doe123") == "username"
    def test_phone(self):
        from argus.plugins.classifier import classify_target
        assert classify_target("+1234567890") == "phone"
    def test_crypto_btc(self):
        from argus.plugins.classifier import classify_target
        assert classify_target("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == "crypto"
    def test_unknown(self):
        from argus.plugins.classifier import classify_target
        assert classify_target("random text here") == "unknown"
    def test_empty(self):
        from argus.plugins.classifier import classify_target
        assert classify_target("") == "unknown"
