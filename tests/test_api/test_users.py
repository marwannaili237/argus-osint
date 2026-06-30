import pytest
class TestUserSchemas:
    def test_user_model_fields(self):
        from argus.models.user import User
        assert hasattr(User, "username")
        assert hasattr(User, "email")
        assert hasattr(User, "role")
    def test_api_key_model(self):
        from argus.models.user import APIKey
        assert hasattr(APIKey, "key_hash")
        assert hasattr(APIKey, "rate_limit")
    def test_user_roles(self):
        for role in ["admin", "analyst", "viewer", "auditor"]:
            assert isinstance(role, str)
    def test_router_exists(self):
        from argus.api.users import router
        assert router is not None
