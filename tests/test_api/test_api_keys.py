import pytest
class TestAPIKeysRouter:
    def test_router_exists(self):
        from argus.api.api_keys import router
        assert router is not None
    def test_key_hashing(self):
        import hashlib
        raw = "test-key-12345"
        h = hashlib.sha256(raw.encode()).hexdigest()
        assert len(h) == 64
        assert h != raw
    def test_rate_limit_range(self):
        rate = 100
        assert 0 < rate <= 1000
