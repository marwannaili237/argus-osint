import pytest
class TestPII:
    def test_redact_email(self):
        from argus.security.pii_redact import redact_pii
        r = redact_pii("Contact user@example.com for info")
        assert "user@example.com" not in r
    def test_redact_phone(self):
        from argus.security.pii_redact import redact_pii
        r = redact_pii("Call +1234567890123 now")
        assert "+1234567890123" not in r or "***" in r
    def test_no_pii(self):
        from argus.security.pii_redact import redact_pii
        r = redact_pii("Hello world test message")
        assert "Hello world" in r
