"""AI report generator plugin - compiles all plugin results into a structured report."""
import logging
from datetime import datetime, timezone
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class AIReportGeneratorPlugin(BasePlugin):
    name = "ai_report_generator"
    target_types = ["domain", "ip", "email", "username", "company", "person"]
    timeout_seconds = 10

    async def run(self, target: str) -> PluginResult:
        """Generate a structured investigation report from all available plugin results for this target."""
        from argus.database import async_session_factory
        from argus.models.target import Target
        from argus.models.plugin_result import PluginResult as PRModel
        from sqlalchemy import select

        findings = []
        risk_level = "info"
        total_findings = 0
        high_risk_count = 0
        medium_risk_count = 0
        low_risk_count = 0
        recommendations = []
        timeline = []

        try:
            async with async_session_factory() as db:
                # Find the target in database
                stmt = select(Target).where(Target.value == target)
                result = await db.execute(stmt)
                target_obj = result.scalar_one_or_none()

                if target_obj:
                    # Get all plugin results for this target
                    stmt = select(PRModel).where(PRModel.target_id == target_obj.id).order_by(PRModel.created_at)
                    result = await db.execute(stmt)
                    prs = result.scalars().all()

                    for pr in prs:
                        finding_risk = "low"
                        detail = {}

                        # Assess risk based on plugin name and data
                        if pr.status == "error":
                            finding_risk = "info"
                            detail = {"error": pr.error_message}
                        elif pr.plugin_name in ("ai_threat_scoring",):
                            score = (pr.data or {}).get("threat_score", 0)
                            if score >= 75:
                                finding_risk = "critical"
                            elif score >= 55:
                                finding_risk = "high"
                            elif score >= 35:
                                finding_risk = "medium"
                            detail = pr.data or {}
                        elif pr.plugin_name in ("security_headers",):
                            grade = (pr.data or {}).get("grade", "")
                            if grade in ("D", "F"):
                                finding_risk = "high"
                            elif grade == "C":
                                finding_risk = "medium"
                            detail = pr.data or {}
                        elif pr.plugin_name in ("honeypot_detector", "darkweb"):
                            if (pr.data or {}).get("honeyscore", 0) > 0.5 or (pr.data or {}).get("exposed_credentials", False):
                                finding_risk = "critical"
                            else:
                                finding_risk = "medium"
                            detail = pr.data or {}
                        elif pr.plugin_name in ("network_zone_transfer",):
                            if (pr.data or {}).get("zone_transfer_possible", False):
                                finding_risk = "critical"
                            else:
                                finding_risk = "low"
                            detail = pr.data or {}
                        else:
                            detail = pr.data or {}
                            if detail.get("has_captcha") or detail.get("waf_detected"):
                                finding_risk = "low"  # Security measures are good

                        findings.append({
                            "plugin": pr.plugin_name,
                            "status": pr.status,
                            "risk": finding_risk,
                            "data": detail,
                            "execution_time": pr.execution_time,
                        })
                        timeline.append({
                            "time": pr.created_at.isoformat() if pr.created_at else "",
                            "event": f"{pr.plugin_name}: {pr.status}",
                        })
                        total_findings += 1

                        if finding_risk in ("critical", "high"):
                            high_risk_count += 1
                        elif finding_risk == "medium":
                            medium_risk_count += 1
                        else:
                            low_risk_count += 1

        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            findings.append({"plugin": "error", "status": "error", "risk": "info", "data": {"error": str(e)}})

        # Determine overall risk
        if high_risk_count > 0:
            risk_level = "high"
        elif medium_risk_count > 2:
            risk_level = "medium"
        elif total_findings == 0:
            risk_level = "info"

        # Generate recommendations
        if high_risk_count > 0:
            recommendations.append(f"URGENT: {high_risk_count} high-risk findings require immediate attention")
        if any(f["plugin"] == "security_headers" and f["data"].get("grade") in ("D", "F") for f in findings):
            recommendations.append("Implement missing security headers (CSP, HSTS, X-Frame-Options)")
        if any(f["plugin"] == "network_zone_transfer" and f["data"].get("zone_transfer_possible") for f in findings):
            recommendations.append("CRITICAL: DNS zone transfer is enabled. Disable immediately.")
        if any(f["plugin"] == "web_broken_links" and f["data"].get("broken_percentage", 0) > 10 for f in findings):
            recommendations.append("Fix broken links ({broken_percentage}% broken detected)")
        if not recommendations:
            recommendations.append("No critical issues detected. Continue monitoring.")

        # Build summary
        summary = f"Investigation report for '{target}': {total_findings} plugins executed. "
        summary += f"Risk level: {risk_level.upper()}. "
        summary += f"Findings: {high_risk_count} high, {medium_risk_count} medium, {low_risk_count} low."

        return PluginResult(
            plugin_name=self.name, status="success",
            data={
                "report": {
                    "summary": summary,
                    "findings": findings,
                    "risk_assessment": {
                        "overall_level": risk_level,
                        "high_risk": high_risk_count,
                        "medium_risk": medium_risk_count,
                        "low_risk": low_risk_count,
                        "total": total_findings,
                    },
                    "recommendations": recommendations,
                    "timeline": timeline,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                },
                "format": "structured",
            },
        )
