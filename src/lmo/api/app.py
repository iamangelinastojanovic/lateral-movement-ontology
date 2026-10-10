"""FastAPI factory: one read-only warehouse, one lock, LmoError as HTTP."""

from __future__ import annotations

import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from lmo.api.routes import register_routes
from lmo.errors import LmoError
from lmo.ingest.engine import Warehouse

STATIC_DIR = Path(__file__).resolve().parent.parent / "web" / "static"


def _status_for(exc: LmoError) -> int:
    problem = exc.problem.lower()
    if any(
        token in problem
        for token in ("no alert", "no account", "no host", "no event", "no incident")
    ):
        return 404
    if any(
        token in problem
        for token in ("out of date", "no detect run", "no graph")
    ):
        return 409
    if "no warehouse" in problem:
        return 503
    return 400


def create_app(
    db_path: str | Path,
    *,
    source: str | Path | None = None,
) -> FastAPI:
    db_path = Path(db_path)
    source_dir = Path(source) if source is not None else None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.wh = Warehouse(db_path, read_only=False)
        app.state.lock = threading.Lock()
        app.state.source = source_dir
        try:
            yield
        finally:
            app.state.wh.close()

    app = FastAPI(
        title="Lateral Movement Ontology",
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )

    @app.exception_handler(LmoError)
    async def lmo_error_handler(_request: Request, exc: LmoError) -> JSONResponse:
        return JSONResponse(
            {"problem": exc.problem, "fix": exc.fix or ""},
            status_code=_status_for(exc),
        )

    register_routes(app)

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html", media_type="text/html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app
