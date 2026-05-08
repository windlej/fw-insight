"""FastAPI application entry point."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from api.storage import init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="fw-insight",
    description="Firewall configuration visualization and analysis platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/api/v1/parsers")
def list_parsers():
    from parsers import list_parsers
    return {"parsers": list_parsers()}


from api.routes import analysis, diff, export, sessions, upload

app.include_router(upload.router, prefix="/api/v1", tags=["upload"])
app.include_router(sessions.router, prefix="/api/v1", tags=["sessions"])
app.include_router(analysis.router, prefix="/api/v1", tags=["analysis"])
app.include_router(diff.router, prefix="/api/v1", tags=["diff"])
app.include_router(export.router, prefix="/api/v1", tags=["export"])

static_dir = Path(__file__).parent.parent / "static"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")
    logger.info("Serving static files from %s", static_dir)
else:
    logger.warning("Static directory not found at %s", static_dir)
