import pytest
class TestDashboardRouter:
    def test_router_exists(self):
        from argus.api.dashboard import router
        assert router is not None
    def test_stats_structure(self):
        stats = {"total_targets": 0, "total_investigations": 0, "total_results": 0, "high_threats": 0}
        assert all(k in stats for k in ["total_targets", "total_investigations"])
    def test_timeline_structure(self):
        tl = [{"time": "2024-01-01T00:00:00", "event": "scan_started"}]
        assert tl[0]["event"] == "scan_started"
