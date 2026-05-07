"""Analysis routes - GET /api/v1/sessions/{id}/analysis."""

from fastapi import APIRouter, HTTPException

from api.storage import get_session, get_findings

router = APIRouter()


@router.get("/sessions/{session_id}/analysis")
def get_analysis(session_id: str):
    """Get analysis results for a session."""
    session = get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    findings = get_findings(session_id)

    return {
        "session_id": session_id,
        "health_score": session["health_score"],
        "finding_counts": session["finding_counts"],
        "findings": findings,
    }
