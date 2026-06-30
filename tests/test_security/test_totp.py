import pytest
class TestTOTP:
    def test_secret(self):
        from argus.security.totp import generate_totp_secret
        s = generate_totp_secret()
        assert isinstance(s, str) and len(s) >= 16
    def test_wrong_code(self):
        from argus.security.totp import verify_totp
        assert isinstance(verify_totp("A" * 32, "000000"), bool)
    def test_uri(self):
        from argus.security.totp import get_totp_provisioning_uri
        uri = get_totp_provisioning_uri("KEY", "user@example.com")
        assert "otpauth://" in uri
