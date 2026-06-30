"""AI natural language query parser plugin."""
import re
import logging
from argus.plugins.runner import BasePlugin, PluginResult
from argus.plugins.classifier import classify_target

logger = logging.getLogger(__name__)

INTENT_PATTERNS = {
    "scan": [r'(?i)(?:scan|investigate|analyze|check|look[\s]+up|osint)'],
    "lookup": [r'(?i)(?:what[\s]+is|who[\s]+is|find|search|lookup|resolve)'],
    "compare": [r'(?i)(?:compare|diff|difference|versus|vs)'],
    "monitor": [r'(?i)(?:monitor|watch|track|alert|notify)'],
    "export": [r'(?i)(?:export|download|save|report|generate)'],
}

ENTITY_PATTERNS = {
    "email": r'[\w.-]+@[\w.-]+\.\w{2,}',
    "ip": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    "domain": r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|net|org|io|co|ru|cn|de|uk|fr|info|biz|xyz|dev|app|me|tv)\b',
    "url": r'https?://[^\s<>"]+',
    "phone": r'\+?\d[\d\s-]{8,}\d',
    "username": r'@?(?:[a-zA-Z0-9_]){3,20}',
    "hash": r'\b[a-fA-F0-9]{32,64}\b',
    "cve": r'CVE-\d{4}-\d{4,}',
}


class AINLQueryPlugin(BasePlugin):
    name = "ai_nl_query"
    target_types = ["unknown"]
    timeout_seconds = 5

    async def run(self, target: str) -> PluginResult:
        """Parse natural language queries to extract targets, intent, and entities."""
        parsed_targets = []
        intent = "scan"
        entities = []
        suggested_queries = []

        # Detect intent
        for intent_name, patterns in INTENT_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, target):
                    intent = intent_name
                    break
            else:
                continue
            break

        # Extract entities
        for entity_type, pattern in ENTITY_PATTERNS.items():
            for match in re.finditer(pattern, target):
                value = match.group(0)
                if len(value) >= 3:
                    classified = classify_target(value)
                    entities.append({"type": entity_type, "value": value, "classified_as": classified})
                    parsed_targets.append({"value": value, "type": classified, "source": entity_type})

        # If no entities found, treat the whole input as a potential target
        if not parsed_targets:
            cleaned = target.strip().strip('"').strip("'")
            classified = classify_target(cleaned)
            parsed_targets.append({"value": cleaned, "type": classified, "source": "full_query"})
        
        # Generate suggested follow-up queries
        for pt in parsed_targets:
            val = pt["value"]
            suggested_queries.append(f"scan {val}")
            if pt["type"] == "domain":
                suggested_queries.append(f"whois {val}")
                suggested_queries.append(f"dns {val}")
            elif pt["type"] == "ip":
                suggested_queries.append(f"geo {val}")
                suggested_queries.append(f"ports {val}")
            elif pt["type"] == "email":
                suggested_queries.append(f"verify {val}")

        return PluginResult(
            plugin_name=self.name, status="success",
            data={
                "parsed_targets": parsed_targets,
                "intent": intent,
                "entities": entities,
                "suggested_queries": list(set(suggested_queries))[:10],
            },
        )
