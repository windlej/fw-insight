"""Diff routes - POST /api/v1/diff."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from api.storage import get_session
from core.diff import diff_sessions
from core.models import Session

router = APIRouter()


class DiffRequest(BaseModel):
    session_a_id: str
    session_b_id: str


@router.post("/diff")
def diff_configs(request: DiffRequest):
    """Compare two sessions and return a diff."""
    session_a_data = get_session(request.session_a_id)
    if session_a_data is None:
        raise HTTPException(status_code=404, detail=f"Session {request.session_a_id} not found")

    session_b_data = get_session(request.session_b_id)
    if session_b_data is None:
        raise HTTPException(status_code=404, detail=f"Session {request.session_b_id} not found")

    session_a = Session.model_validate(session_a_data)
    session_b = Session.model_validate(session_b_data)

    diff = diff_sessions(session_a, session_b)

    return diff.model_dump()
