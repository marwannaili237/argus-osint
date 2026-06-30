import pytest
class TestPluginSystem:
    def test_result_creation(self):
        from argus.plugins.runner import PluginResult
        r = PluginResult(plugin_name="test", status="success", data={"key": "val"})
        assert r.plugin_name == "test"
        assert r.status == "success"
    def test_result_error(self):
        from argus.plugins.runner import PluginResult
        r = PluginResult(plugin_name="test", status="error", data={}, error_message="fail")
        assert r.error_message == "fail"
    def test_result_timing(self):
        from argus.plugins.runner import PluginResult
        r = PluginResult(plugin_name="test", status="success", data={}, execution_time=1.234)
        assert r.execution_time == 1.234
    def test_result_cached(self):
        from argus.plugins.runner import PluginResult
        r = PluginResult(plugin_name="test", status="success", data={}, cached=True)
        assert r.cached is True
    def test_registry_empty(self):
        from argus.plugins.runner import PluginRegistry
        reg = PluginRegistry()
        assert len(reg.get_all()) == 0
    def test_plugin_info(self):
        from argus.plugins.runner import PluginInfo, BasePlugin
        class Mock(BasePlugin):
            name = "mock"; target_types = ["domain"]
            async def run(self, target): return None
        info = PluginInfo(Mock())
        assert info.name == "mock"
    def test_plugin_error(self):
        from argus.plugins.runner import PluginError
        with pytest.raises(PluginError):
            raise PluginError("err")
    def test_timeout_is_error(self):
        from argus.plugins.runner import PluginTimeoutError, PluginError
        assert issubclass(PluginTimeoutError, PluginError)
    @pytest.mark.asyncio
    async def test_run_not_found(self):
        from argus.plugins.runner import run_plugin
        r = await run_plugin("nonexistent", "example.com")
        assert r.status == "error"
    @pytest.mark.asyncio
    async def test_run_all_empty(self):
        from argus.plugins.runner import run_all_for_target
        r = await run_all_for_target("x", "unknown_xyz")
        assert r == []
