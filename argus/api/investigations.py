"""
Argus OSINT – Investigations API Router

CRUD operations for investigations with access control, target management,
and PDF/CSV export capabilities.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from argus.database import get_db
from argus.models.investigation import Investigation
from argus.models.plugin_result import PluginResult
from argus.models.target import Target, target_investigation
from argus.schemas.investigation import (
    InvestigationCreate,
    InvestigationListResponse,
    InvestigationResponse,
    InvestigationUpdate,
)
from argus.security.rbac import (
    Permission,
    check_investigation_access,
    require_permission,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/investigations", tags=["investigations"])


# ── Helpers ─────────────────────────────────────────────────────────

async def _get_investigation_or_404(
    investigation_id: int,
    db: AsyncSession,
) -> Investigation:
    result = await db.execute(
        select(Investigation)
        .options(selectinload(Investigation.targets))
        .where(Investigation.id == investigation_id)
    )
    inv = result.scalar_one_or_none()
    if inv is None:
        raise HTTPException(status_code=404, detail=f"Investigation {investigation_id} not found")
    return inv


def _check_access_or_403(
    request_or_user,
    investigation: Investigation,
    permission: Permission = Permission.INVESTIGATION_READ,
) -> None:
    """Raise 403 if the current user lacks access."""
    from fastapi import Request
    user = None
    if isinstance(request_or_user, Request):
        user = getattr(request_or_user, "current_user", None)
    else:
        user = request_or_user

    if not check_investigation_access(user, investigation, permission):
        raise HTTPException(status_code=403, detail="Access denied to this investigation")


# ── Endpoints ───────────────────────────────────────────────────────

@router.post("/", response_model=InvestigationResponse, status_code=201)
async def create_investigation(
    payload: InvestigationCreate,
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.INVESTIGATION_CREATE)),
) -> Investigation:
    """Create a new investigation with optional attached targets."""
    investigation = Investigation(
        name=payload.name,
        description=payload.description,
        priority=payload.priority,
        tags=payload.tags,
        classification=payload.classification,
        # created_by will be set from auth context; default to 0 if unauthenticated
    )

    # Attach existing targets
    if payload.target_ids:
        targets_result = await db.execute(
            select(Target).where(Target.id.in_(payload.target_ids))
        )
        found_targets = targets_result.scalars().all()
        if len(found_targets) != len(payload.target_ids):
            found_ids = {t.id for t in found_targets}
            missing = set(payload.target_ids) - found_ids
            raise HTTPException(
                status_code=400,
                detail=f"Target IDs not found: {sorted(missing)}",
            )
        investigation.targets = list(found_targets)

    db.add(investigation)
    await db.flush()
    await db.refresh(investigation)
    return investigation


@router.get("/", response_model=InvestigationListResponse)
async def list_investigations(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    status: Optional[str] = Query(default=None),
    classification: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.INVESTIGATION_READ)),
) -> InvestigationListResponse:
    """List investigations with pagination and optional filters."""
    query = select(Investigation).options(selectinload(Investigation.targets))
    count_query = select(func.count(Investigation.id))

    if status is not None:
        query = query.where(Investigation.status == status)
        count_query = count_query.where(Investigation.status == status)
    if classification is not None:
        query = query.where(Investigation.classification == classification)
        count_query = count_query.where(Investigation.classification == classification)

    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    offset = (page - 1) * per_page
    query = query.order_by(Investigation.created_at.desc()).offset(offset).limit(per_page)
    result = await db.execute(query)
    investigations = result.scalars().all()

    return InvestigationListResponse(
        items=[InvestigationResponse.model_validate(inv) for inv in investigations],
        total=total,
        page=page,
    )


@router.get("/{investigation_id}", response_model=InvestigationResponse)
async def get_investigation(
    investigation_id: int,
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.INVESTIGATION_READ)),
) -> Investigation:
    """Retrieve a single investigation by ID."""
    inv = await _get_investigation_or_404(investigation_id, db)
    return inv


@router.put("/{investigation_id}", response_model=InvestigationResponse)
async def update_investigation(
    investigation_id: int,
    payload: InvestigationUpdate,
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.INVESTIGATION_UPDATE)),
) -> Investigation:
    """Update an existing investigation's metadata."""
    inv = await _get_investigation_or_404(investigation_id, db)

    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(inv, key, value)

    await db.flush()
    await db.refresh(inv)
    return inv


@router.delete("/{investigation_id}", status_code=204)
async def delete_investigation(
    investigation_id: int,
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.INVESTIGATION_DELETE)),
) -> None:
    """Delete an investigation."""
    inv = await _get_investigation_or_404(investigation_id, db)
    await db.delete(inv)
    await db.flush()


@router.post("/{investigation_id}/targets", response_model=InvestigationResponse)
async def add_target_to_investigation(
    investigation_id: int,
    target_ids: list[int],
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.INVESTIGATION_UPDATE)),
) -> Investigation:
    """Attach one or more existing targets to an investigation."""
    inv = await _get_investigation_or_404(investigation_id, db)

    targets_result = await db.execute(
        select(Target).where(Target.id.in_(target_ids))
    )
    new_targets = targets_result.scalars().all()

    existing_ids = {t.id for t in inv.targets}
    added = 0
    for t in new_targets:
        if t.id not in existing_ids:
            inv.targets.append(t)
            added += 1

    await db.flush()
    await db.refresh(inv)
    return inv


@router.post("/{investigation_id}/export/pdf")
async def export_investigation_pdf(
    investigation_id: int,
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.INVESTIGATION_EXPORT)),
) -> Response:
    """Generate a PDF report for an investigation."""
    inv = await _get_investigation_or_404(investigation_id, db)

    # Collect all plugin results for targets in this investigation
    target_ids = [t.id for t in inv.targets]
    if target_ids:
        results = await db.execute(
            select(PluginResult)
            .where(PluginResult.target_id.in_(target_ids))
            .order_by(PluginResult.created_at.desc())
        )
        plugin_results = results.scalars().all()
    else:
        plugin_results = []

    # Generate a simple PDF using reportlab
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()

    elements: list = []

    # Title
    elements.append(Paragraph(f"Investigation: {inv.name}", styles["Heading1"]))
    elements.append(Paragraph(inv.description or "No description", styles["Normal"]))
    elements.append(Spacer(1, 6 * mm))
    elements.append(Paragraph(
        f"Classification: {inv.classification} | Status: {inv.status} | Priority: {inv.priority}",
        styles["Normal"],
    ))
    elements.append(Spacer(1, 6 * mm))

    # Targets table
    if inv.targets:
        target_data = [["Target Type", "Value", "Status", "Priority"]]
        for t in inv.targets:
            target_data.append([t.type, t.value, t.status, str(t.priority)])

        table = Table(target_data, colWidths=[80, 250, 80, 60])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), "#333333"),
            ("TEXTCOLOR", (0, 0), (-1, 0), "#FFFFFF"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, "#CCCCCC"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), ["#F5F5F5", "#FFFFFF"]),
        ]))
        elements.append(Paragraph("Targets", styles["Heading2"]))
        elements.append(table)
    else:
        elements.append(Paragraph("No targets attached.", styles["Normal"]))

    elements.append(Spacer(1, 6 * mm))

    # Plugin results summary
    if plugin_results:
        result_data = [["Plugin", "Target", "Status", "Time (s)"]]
        for pr in plugin_results[:50]:  # Limit to 50 rows for PDF
            target_val = pr.target.value if pr.target else "N/A"
            result_data.append([pr.plugin_name, target_val[:40], pr.status, f"{pr.execution_time:.2f}"])

        result_table = Table(result_data, colWidths=[120, 180, 80, 60])
        result_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), "#333333"),
            ("TEXTCOLOR", (0, 0), (-1, 0), "#FFFFFF"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, "#CCCCCC"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), ["#F5F5F5", "#FFFFFF"]),
        ]))
        elements.append(Paragraph("Plugin Results", styles["Heading2"]))
        elements.append(result_table)

    doc.build(elements)
    buffer.seek(0)

    return Response(
        content=buffer.getvalue(),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="investigation_{inv.id}_report.pdf"',
        },
    )


@router.post("/{investigation_id}/export/csv")
async def export_investigation_csv(
    investigation_id: int,
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(require_permission(Permission.INVESTIGATION_EXPORT)),
) -> StreamingResponse:
    """Generate a CSV export for an investigation."""
    inv = await _get_investigation_or_404(investigation_id, db)

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "Investigation ID", "Name", "Status", "Classification", "Priority",
        "Target ID", "Target Type", "Target Value", "Target Status",
        "Plugin", "Plugin Status", "Execution Time", "Error",
    ])

    for target in inv.targets:
        # Get plugin results for this target
        pr_result = await db.execute(
            select(PluginResult)
            .where(PluginResult.target_id == target.id)
            .order_by(PluginResult.created_at.desc())
        )
        plugin_results = pr_result.scalars().all()

        if plugin_results:
            for pr in plugin_results:
                writer.writerow([
                    inv.id, inv.name, inv.status, inv.classification, inv.priority,
                    target.id, target.type, target.value, target.status,
                    pr.plugin_name, pr.status, pr.execution_time, pr.error_message or "",
                ])
        else:
            writer.writerow([
                inv.id, inv.name, inv.status, inv.classification, inv.priority,
                target.id, target.type, target.value, target.status,
                "", "", "", "",
            ])

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="investigation_{inv.id}_export.csv"',
        },
    )
