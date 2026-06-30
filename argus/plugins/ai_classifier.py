"""AI-based target classifier plugin using rule-based intelligence."""
import re
import logging
from argus.plugins.runner import BasePlugin, PluginResult
from argus.plugins.classifier import classify_target

logger = logging.getLogger(__name__)

# Confidence boosters for specific patterns
CONFIDENCE_BOOSTERS = {
    "domain": [r'^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}$'],
    "ip": [r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'],
    "email": [r'^[\w.-]+@[\w.-]+\.\w+$'],
    "url": [r'^https?://'],
    "username": [r'^[a-zA-Z0-9_]{3,20}$'],
    "phone": [r'^\+?[\d-]{10,15}$'],
    "crypto": [r'^(0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})$'],
}

# Context clues for alternative type suggestions
CONTEXT_CLUES = {
    "person": [r'\b(inc|ltd|corp|llc|gmbh|s\.a\.|ag)\b', r'\b(mr|mrs|dr|prof)\b'],
    "company": [r'\b(inc|ltd|corp|llc|gmbh|s\.a\.|ag|company)\b'],
    "cve": [r'^CVE-\d{4}-\d{4,}$', r'^GHSA-'],
    "hash": [r'^[a-fA-F0-9]{32,64}$'],
    "bitcoin": [r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$'],
    "ethereum": [r'^0x[a-fA-F0-9]{40}$'],
}


class AIClassifierPlugin(BasePlugin):
    name = "ai_classifier"
    target_types = ["unknown", "domain", "ip", "email", "url", "username"]
    timeout_seconds = 5

    async def run(self, target: str) -> PluginResult:
        """Classify target with confidence scoring and alternative suggestions."""
        primary_type = classify_target(target)
        confidence = 75.0
        alternatives = []
        reasoning = []

        # Boost confidence if target matches specific patterns well
        for ttype, patterns in CONFIDENCE_BOOSTERS.items():
            if ttype == primary_type:
                for pat in patterns:
                    if re.fullmatch(pat, target):
                        confidence = 95.0
                        reasoning.append(f"Matches {ttype} pattern precisely")
                        break

        # Check for alternative types
        for alt_type, patterns in CONTEXT_CLUES.items():
            for pat in patterns:
                if re.search(pat, target, re.IGNORECASE):
                    if alt_type != primary_type:
                        alternatives.append(alt_type)
                        reasoning.append(f"Contains clue suggesting {alt_type}")

        # Special heuristics
        if target.count('@') == 1 and '.' not in target.split('@')[-1]:
            alternatives.append('email')
            reasoning.append('Has @ but no valid domain TLD')

        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            octets = target.split('.')
            if all(0 <= int(o) <= 255 for o in octets):
                confidence = 95.0
            else:
                confidence = 30.0
                reasoning.append('IP octets out of valid range')

        if primary_type == 'unknown' and not alternatives:
            confidence = 20.0
            reasoning.append('No matching patterns found')

        return PluginResult(
            plugin_name=self.name, status='success',
            data={
                'classification': primary_type,
                'confidence': confidence,
                'alternative_types': list(set(alternatives)),
                'reasoning': reasoning,
            },
        )
