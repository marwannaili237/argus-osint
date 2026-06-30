import pytest
class TestUser:
    def test_user_fields(self):
        from argus.models.user import User
        for f in ["username", "email", "role", "two_factor_enabled"]:
            assert hasattr(User, f)
    def test_apikey_fields(self):
        from argus.models.user import APIKey
        for f in ["key_hash", "rate_limit", "permissions", "expires_at"]:
            assert hasattr(APIKey, f)
