import pytest
class TestIPAllowlist:
    def test_empty_allows_all(self):
        from argus.security.ip_allowlist import check_ip_allowlist, reset_allowlist_cache
        reset_allowlist_cache()
        assert check_ip_allowlist("192.168.1.1") is True
    def test_returns_bool(self):
        from argus.security.ip_allowlist import check_ip_allowlist
        assert isinstance(check_ip_allowlist("10.0.0.1"), bool)
