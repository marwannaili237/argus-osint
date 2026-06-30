"""AI IOC (Indicator of Compromise) extraction plugin."""
import re
import logging
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)

IOC_PATTERNS = {
    "ipv4": {"pattern": r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', "severity": "medium"},
    "ipv6": {"pattern": r'\b([0-9a-fA-F:]{2,39})\b', "severity": "medium"},
    "url": {"pattern": r'https?://[^\s<>"]+', "severity": "high"},
    "email": {"pattern": r'[\w.-]+@[\w.-]+\.\w{2,}', "severity": "low"},
    "domain": {"pattern": r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|net|org|io|co|ru|cn|de|uk|fr|br|in|jp|au|ca|xyz|info|biz)[^\s]*)', "severity": "medium"},
    "md5_hash": {"pattern": r'\b[a-fA-F0-9]{32}\b', "severity": "high"},
    "sha1_hash": {"pattern": r'\b[a-fA-F0-9]{40}\b', "severity": "high"},
    "sha256_hash": {"pattern": r'\b[a-fA-F0-9]{64}\b', "severity": "high"},
    "bitcoin_address": {"pattern": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', "severity": "medium"},
    "cve": {"pattern": r'\bCVE-\d{4}-\d{4,}\b', "severity": "high"},
    "file_path": {"pattern": r'(?:C:|/)(?:[\w/\\.-]+)\.(?:exe|dll|ps1|bat|sh|py|js|vbs|cmd|msh)', "severity": "high"},
    "registry_key": {"pattern": r'HKEY_[A-Z_]+\\[\w\\]+', "severity": "high"},
}


class AIIOCExtractionPlugin(BasePlugin):
    name = "ai_ioc"
    target_types = ["domain", "ip", "url", "email", "username", "unknown"]
    timeout_seconds = 10

    async def run(self, target: str) -> PluginResult:
        """Extract indicators of compromise from the target value and context."""
        iocs = []
        severity_distribution = {}

        # Run all IOC patterns against the target value
        for ioc_type, config in IOC_PATTERNS.items():
            matches = re.findall(config["pattern"], target, re.IGNORECASE)
            for match in matches:
                val = match if isinstance(match, str) else match[0] if match else ""
                if not val or len(val) < 3:
                    continue
                severity = config["severity"]
                iocs.append({
                    "type": ioc_type,
                    "value": val[:200],
                    "severity": severity,
                    "source": "pattern_extraction",
                })
                severity_distribution[severity] = severity_distribution.get(severity, 0) + 1

        # Also check if target itself is an IOC
        target_ioc_type = self._classify_as_ioc(target)
        if target_ioc_type:
            # Avoid duplicate if already found by pattern
            if not any(i["value"] == target for i in iocs):
                iocs.insert(0, {
                    "type": target_ioc_type,
                    "value": target,
                    "severity": "medium",
                    "source": "direct_target",
                })
                severity_distribution["medium"] = severity_distribution.get("medium", 0) + 1

        return PluginResult(
            plugin_name=self.name, status="success",
            data={
                "iocs": iocs,
                "total_iocs": len(iocs),
                "severity_distribution": severity_distribution,
            },
        )

    def _classify_as_ioc(self, value: str) -> str | None:
        """Check if the target value itself is a known IOC type."""
        if re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', value):
            return "ipv4"
        if re.fullmatch(r'[a-fA-F0-9]{32}', value):
            return "md5_hash"
        if re.fullmatch(r'[a-fA-F0-9]{64}', value):
            return "sha256_hash"
        if re.fullmatch(r'CVE-\d{4}-\d{4,}', value, re.IGNORECASE):
            return "cve"
        return None
