import pytest
class TestTarget:
    def test_fields(self):
        from argus.models.target import Target
        for f in ["id", "type", "value", "status", "priority"]:
            assert hasattr(Target, f)
    def test_valid_types(self):
        for t in ["domain", "url", "ip", "email", "username", "phone", "image", "person", "company", "crypto", "unknown"]:
            assert isinstance(t, str)
