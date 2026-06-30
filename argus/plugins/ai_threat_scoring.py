"""AI threat scoring plugin - assesses threat level based on multiple factors."""
import re
import logging
import dns.resolver
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)

# Factor weights for threat scoring
FACTOR_WEIGHTS = {
    "domain_age": 15,
    "dns_records": 10,
    "security_headers": 15,
    "ssl_valid": 10,
    "reputation": 25,
    "data_exposure": 15,
    "infrastructure_risk": 10,
}


class AIThreatScoringPlugin(BasePlugin):
    name = "ai_threat_scoring"
    target_types = ["domain", "ip", "email", "url"]
    timeout_seconds = 30

    async def run(self, target: str) -> PluginResult:
        """Score threat level based on multiple heuristic factors."""
        score = 0.0
        factors = []
        max_score = sum(FACTOR_WEIGHTS.values())

        # Factor 1: Domain age (newer = more suspicious)
        domain = target if '.' in target and not target.startswith('http') else target
        if domain.startswith('http'):
            from urllib.parse import urlparse
            domain = urlparse(domain).netloc
        if '@' in domain:
            domain = domain.split('@')[-1]

        domain_age_score = 0
        try:
            import subprocess
            proc = await __import__('asyncio').create_subprocess_exec(
                'whois', domain,
                stdout=__import__('asyncio').subprocess.PIPE,
                stderr=__import__('asyncio').subprocess.PIPE,
            )
            stdout, _ = await __import__('asyncio').wait_for(proc.communicate(), timeout=10)
            output = stdout.decode('utf-8', errors='replace').lower()
            if 'creation' in output or 'registered' in output:
                # Try to extract year
                year_match = re.search(r'(creation|registered).*?(20\d{2})', output)
                if year_match:
                    year = int(year_match.group(2))
                    import datetime
                    age = datetime.datetime.now().year - year
                    if age < 1:
                        domain_age_score = 100
                    elif age < 2:
                        domain_age_score = 70
                    elif age < 5:
                        domain_age_score = 40
                    else:
                        domain_age_score = 10
        except Exception:
            domain_age_score = 30  # Unknown = moderate risk
        score += (domain_age_score / 100) * FACTOR_WEIGHTS["domain_age"]
        factors.append({"name": "domain_age", "score": domain_age_score, "max": 100, "detail": f"{'New domain' if domain_age_score > 50 else 'Established domain' if domain_age_score < 30 else 'Unknown age'}"})

        # Factor 2: DNS record analysis
        dns_score = 0
        try:
            answers = dns.resolver.resolve(domain, 'A')
            dns_score += 20  # Has A record
        except Exception:
            dns_score += 50  # No A record is suspicious
        try:
            dns.resolver.resolve(domain, 'MX')
            dns_score += 10
        except Exception:
            pass
        try:
            dns.resolver.resolve(domain, 'NS')
            dns_score += 10
        except Exception:
            dns_score += 30
        score += (min(dns_score, 100) / 100) * FACTOR_WEIGHTS["dns_records"]
        factors.append({"name": "dns_records", "score": min(dns_score, 100), "max": 100, "detail": "DNS analysis complete"})

        # Factor 3: TLD risk (certain TLDs are higher risk)
        tld = domain.split('.')[-1].lower() if '.' in domain else ''
        high_risk_tlds = {'xyz', 'top', 'work', 'click', 'info', 'biz', 'tk', 'ml', 'ga', 'cf', 'gq'}
        tld_score = 80 if tld in high_risk_tlds else 20
        score += (tld_score / 100) * FACTOR_WEIGHTS["reputation"]
        factors.append({"name": "tld_risk", "score": tld_score, "max": 100, "detail": f"TLD: .{tld}"})

        # Factor 4: Pattern-based risk
        pattern_score = 0
        if re.match(r'^[a-z]{4,20}\d{2,6}\.\w+$', domain, re.IGNORECASE):
            pattern_score += 40  # Random-looking domain
        if len(domain) > 25:
            pattern_score += 20  # Very long domain
        if domain.count('-') > 3:
            pattern_score += 30  # Many hyphens
        score += (min(pattern_score, 100) / 100) * FACTOR_WEIGHTS["data_exposure"]
        factors.append({"name": "pattern_analysis", "score": min(pattern_score, 100), "max": 100, "detail": "Domain name pattern analysis"})

        # Normalize to 0-100
        final_score = round(min(max(score / max_score * 100, 0), 100), 1)

        if final_score >= 75:
            level = "critical"
        elif final_score >= 55:
            level = "high"
        elif final_score >= 35:
            level = "medium"
        elif final_score >= 15:
            level = "low"
        else:
            level = "info"

        recommendations = []
        if final_score >= 55:
            recommendations.append("Further investigation recommended")
        if tld_score > 50:
            recommendations.append(f"High-risk TLD .{tld} detected")
        if domain_age_score > 50:
            recommendations.append("Newly registered domain - higher risk")
        if dns_score > 50:
            recommendations.append("DNS configuration anomalies detected")

        return PluginResult(
            plugin_name=self.name, status="success",
            data={
                "threat_score": final_score,
                "threat_level": level,
                "factors": factors,
                "recommendations": recommendations,
            },
        )
