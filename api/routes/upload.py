"""Upload route - POST /api/v1/sessions."""

import logging

from fastapi import APIRouter, UploadFile, File, Form, HTTPException

from parsers import get_parser, auto_detect_vendor
from core.normalizer import normalize
from core.analysis.engine import AnalysisEngine
from api.storage import save_session

logger = logging.getLogger(__name__)

router = APIRouter()
engine = AnalysisEngine()


@router.post("/sessions")
async def upload_session(
    file: UploadFile = File(...),
    vendor: str | None = Form(None),
):
    """Upload a firewall config file for analysis."""
    raw_content = await file.read()
    filename = file.filename or "unknown"

    if not vendor:
        vendor = auto_detect_vendor(raw_content)
        if not vendor:
            raise HTTPException(
                status_code=400,
                detail="Could not auto-detect vendor. Please specify the vendor parameter.",
            )

    try:
        parser = get_parser(vendor)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        ast = parser.parse(raw_content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse config: {e}")

    try:
        session_data = parser.normalize(ast)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to normalize config: {e}")

    try:
        session_obj = normalize(vendor, session_data, source_filename=filename, source_content=raw_content)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    result = engine.analyze(session_obj)

    session_dict = session_obj.model_dump()
    session_dict["health_score"] = result.health_score
    session_dict["finding_counts"] = result.finding_counts

    findings = [f.model_dump() for f in result.findings]

    session_id = save_session(session_dict, findings, raw_content, filename)

    return {
        "id": session_id,
        "vendor": vendor,
        "hostname": session_obj.hostname,
        "rule_count": session_obj.rule_count,
        "health_score": result.health_score,
        "finding_counts": result.finding_counts,
    }
