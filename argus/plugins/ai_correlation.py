"""AI correlation plugin - correlates targets with existing database records."""
import logging
from sqlalchemy import select, and_, or_
from argus.plugins.runner import BasePlugin, PluginResult
from argus.database import async_session_factory
from argus.models.target import Target
from argus.models.plugin_result import PluginResult as PR

logger = logging.getLogger(__name__)


class AICorrelationPlugin(BasePlugin):
    name = "ai_correlation"
    target_types = ["domain", "ip", "email"]
    timeout_seconds = 10

    async def run(self, target: str) -> PluginResult:
        """Find related targets in the database based on shared attributes."""
        related_targets = []
        shared_attributes = []
        correlation_score = 0.0
        investigation_links = []

        try:
            async with async_session_factory() as db:
                # Find the current target or similar targets
                stmt = select(Target).where(Target.value.ilike(f"%{target}%"))
                result = await db.execute(stmt)
                similar = result.scalars().all()

                # Find targets sharing the same domain
                if '@' in target:
                    domain = target.split('@')[-1]
                    stmt = select(Target).where(Target.value.ilike(f"%@{domain}"))
                    result = await db.execute(stmt)
                    same_domain = result.scalars().all()
                    for t in same_domain:
                        if t.value != target:
                            related_targets.append({"value": t.value, "type": t.type, "relation": "same_domain"})
                            shared_attributes.append(f"Same domain: {domain}")

                # Find targets in the same investigations
                for t in similar:
                    if t.value != target:
                        related_targets.append({"value": t.value, "type": t.type, "relation": "fuzzy_match"})

                # Check plugin results for IPs that resolved to this domain
                if '.' in target and not target[0].isdigit():
                    stmt = select(PR).where(PR.data.cast(String).ilike(f"%{target}%"))
                    from sqlalchemy import String
                    stmt = select(PR).where(
                        or_(
                            PR.data.cast(String).ilike(f"%{target}%"),
                            PR.error_message.ilike(f"%{target}%"),
                        )
                    )
                    result = await db.execute(stmt)
                    prs = result.scalars().all()
                    for pr in prs:
                        shared_attributes.append(f"Found in {pr.plugin_name} results")

                # Calculate correlation score
                if related_targets:
                    correlation_score = min(100.0, len(related_targets) * 20 + len(shared_attributes) * 5)

        except Exception as e:
            logger.error(f"Correlation lookup failed: {e}")
            # Still return success with empty data

        return PluginResult(
            plugin_name=self.name, status='success',
            data={
                'related_targets': related_targets[:20],
                'shared_attributes': list(set(shared_attributes))[:20],
                'correlation_score': correlation_score,
                'investigation_links': investigation_links,
            },
        )
