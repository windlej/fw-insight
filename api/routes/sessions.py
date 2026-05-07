"""Sessions routes - GET/DELETE /api/v1/sessions."""

from fastapi import APIRouter, HTTPException

from api.storage import get_session, list_sessions, delete_session

router = APIRouter()


@router.get("/sessions")
def get_sessions():
    """List all stored sessions."""
    return {"sessions": list_sessions()}


@router.get("/sessions/{session_id}")
def get_session_detail(session_id: str):
    """Get a session by ID."""
    session = get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.delete("/sessions/{session_id}")
def delete_session_endpoint(session_id: str):
    """Delete a session."""
    if not delete_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"deleted": True}
