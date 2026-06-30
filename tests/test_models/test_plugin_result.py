import pytest
class TestPluginResultModel:
    def test_fields(self):
        from argus.models.plugin_result import PluginResult as PR
        for f in ["plugin_name", "status", "data", "execution_time", "cached"]:
            assert hasattr(PR, f)
