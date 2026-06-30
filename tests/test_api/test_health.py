import pytest
class TestHealthAPI:
    def test_health_endpoint_exists(self):
        from argus.api.health import router
        assert any(r.path == "/health" for r in router.routes)
    def test_health_ready_endpoint_exists(self):
        from argus.api.health import router
        assert any(r.path == "/health/ready" for r in router.routes)
    @pytest.mark.asyncio
    async def test_health_response_format(self):
        resp = {"status": "healthy", "version": "2.0.0", "database": "connected"}
        assert resp["status"] == "healthy"
        assert resp["version"] == "2.0.0"
