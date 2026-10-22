import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .config import get_settings
from .db import ensure_indexes, get_db
from .routers import alerts, auth, breach, dashboard, findings, monitors, reports, scans, system

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("ghosttrace")
settings = get_settings()
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.in_memory_db:
        log.warning("MONGODB_URI is not set: using an in-memory database. Everything is lost when the server stops. "
                    "Set MONGODB_URI in .env to keep data.")
    try:
        ensure_indexes(get_db())
    except Exception as exc:  # noqa: BLE001  (a bad URI shouldn't stop the site; requests will report the error)
        log.error("Could not reach MongoDB: %s", exc)
    from .ml.scorer import _model

    _model()  # load (or train on first boot) the risk model before serving
    scheduler = None
    if settings.enable_scheduler:
        from .services.monitoring import start_scheduler

        scheduler = start_scheduler()
    yield
    if scheduler:
        scheduler.shutdown(wait=False)


app = FastAPI(title="GhostTrace API", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Gzip cuts JS, CSS and JSON payloads to roughly a quarter, which matters on slow hosts like Render's free plan.
app.add_middleware(GZipMiddleware, minimum_size=1024)

for r in (auth, scans, findings, dashboard, breach, monitors, alerts, reports, system):
    app.include_router(r.router)


@app.get("/api/health")
def health() -> dict:
    try:
        get_db().command("ping")
        database = "in-memory" if settings.in_memory_db else "connected"
    except Exception:  # noqa: BLE001
        database = "unreachable"
    return {"status": "ok" if database != "unreachable" else "degraded", "app": settings.app_name, "database": database}


# `npm run build` writes the React app to ./static; FastAPI serves it (on Vercel, from the CDN).
if STATIC_DIR.exists():
    class _ImmutableAssets(StaticFiles):
        # Vite fingerprints asset filenames, so browsers can cache them forever and skip revalidation.
        async def get_response(self, path, scope):
            response = await super().get_response(path, scope)
            if response.status_code == 200:
                response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            return response

    app.mount("/assets", _ImmutableAssets(directory=STATIC_DIR / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> FileResponse:
        file = STATIC_DIR / path
        if path and file.is_file() and STATIC_DIR in file.resolve().parents:
            return FileResponse(file)
        return FileResponse(STATIC_DIR / "index.html")
