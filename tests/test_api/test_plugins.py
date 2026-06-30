import pytest
class TestPluginRouter:
    def test_router_exists(self):
        from argus.api.plugins import router
        assert router is not None
    def test_list_endpoint(self):
        from argus.api.plugins import router
        paths = [r.path for r in router.routes]
        assert "/plugins/" in paths
    def test_health_endpoint(self):
        from argus.api.plugins import router
        paths = [r.path for r in router.routes]
        assert any("health" in p for p in paths)
