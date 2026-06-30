import pytest
class TestNetworkPlugins:
    def test_traceroute(self):
        from argus.plugins.network_traceroute import NetworkTraceroutePlugin
        assert NetworkTraceroutePlugin().name == "network_traceroute"
    def test_asn(self):
        from argus.plugins.network_asn import NetworkASNPlugin
        assert NetworkASNPlugin().name == "network_asn"
    def test_cdn_waf(self):
        from argus.plugins.network_cdn_waf import NetworkCdnWafPlugin, CDN_SIGNATURES
        assert len(CDN_SIGNATURES) >= 5
    def test_zone_transfer(self):
        from argus.plugins.network_zone_transfer import NetworkZoneTransferPlugin
        assert NetworkZoneTransferPlugin().name == "network_zone_transfer"
    def test_ipv6(self):
        from argus.plugins.network_ipv6 import NetworkIPv6Plugin
        assert "domain" in NetworkIPv6Plugin.target_types
    def test_dns_monitor(self):
        from argus.plugins.network_dns_monitor import NetworkDnsMonitorPlugin, RESOLVERS
        assert len(RESOLVERS) >= 3
    def test_cert_pinning(self):
        from argus.plugins.network_cert_pinning import NetworkCertPinningPlugin
        assert NetworkCertPinningPlugin().name == "network_cert_pinning"
    def test_version_fp(self):
        from argus.plugins.network_version_fingerprint import NetworkVersionFingerprintPlugin, COMMON_PORTS
        assert len(COMMON_PORTS) >= 15
