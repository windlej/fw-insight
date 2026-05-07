"""Export routes - GET /api/v1/sessions/{id}/export."""

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

from api.storage import get_session, get_findings, get_raw_config
from report.generator import generate_pdf

router = APIRouter()


@router.get("/sessions/{session_id}/export")
def export_session(
    session_id: str,
    format: str = Query(default="json", regex="^(json|pdf)$"),
):
    """Export a session as JSON or PDF."""
    session = get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    findings = get_findings(session_id)

    if format == "json":
        return JSONResponse(content={
            "session": session,
            "findings": findings,
        })

    if format == "pdf":
        raw_config = get_raw_config(session_id)
        pdf_bytes = generate_pdf(session, findings, raw_config)
        from fastapi.responses import Response
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="fw-insight-{session_id[:8]}.pdf"'},
        )
