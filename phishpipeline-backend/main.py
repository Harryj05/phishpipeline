import asyncio
import logging
import os

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from db.database import SessionLocal, URLQueue, get_db, init_db
from routes import admin, analytics, ingest, reports, submit
from services import certstream_listener, html_classifier, url_transformer
from services.model_registry import model_registry
from services.takedown_tracker import TakedownTracker

logger = logging.getLogger(__name__)

app = FastAPI(title="PhishPipeline Backend")

# Local dev origins by default; in production set ALLOWED_ORIGINS_REGEX
# (e.g. on Railway) to your deployed frontend origin — see DEPLOYMENT.md.
_DEFAULT_ORIGINS_REGEX = (
    r"^(https?://localhost:(5173|5174)"
    r"|https?://127\.0\.0\.1:(5173|5174)"
    r"|chrome-extension://.*)$"
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=os.environ.get(
        "ALLOWED_ORIGINS_REGEX", _DEFAULT_ORIGINS_REGEX
    ),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

app.include_router(submit.router)
app.include_router(ingest.router)
app.include_router(admin.router)
app.include_router(reports.router)
app.include_router(analytics.router)

takedown_tracker = TakedownTracker()


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


@app.on_event("startup")
async def on_startup():
    init_db()

    # Backward compatibility: if a retrained version already exists on disk,
    # deploy the newest one so restarts don't silently fall back to the base
    # HuggingFace hub weights. If models/versions/ is empty, url_transformer
    # and html_classifier fall back to loading the hub weights themselves.
    versions = model_registry.list_versions()
    if versions:
        latest_version = max(v["version"] for v in versions)
        try:
            model_registry.deploy(latest_version)
        except Exception as exc:
            logger.error(
                "Failed to deploy existing model version %s at startup: %s",
                latest_version,
                exc,
            )

    # Pre-load both models here so the first classification request isn't
    # slow waiting on a cold model/tokenizer download+load.
    # Set PHISHPIPELINE_SKIP_MODEL_PRELOAD=1 to skip this in local dev/testing
    # environments without access to the model weights (e.g. no internet).
    if not _env_flag("PHISHPIPELINE_SKIP_MODEL_PRELOAD"):
        url_transformer.preload()
        html_classifier.preload()

    db = SessionLocal()
    try:
        db.query(URLQueue).filter(
            URLQueue.label == "phishing",
            URLQueue.reported_at.isnot(None),
            URLQueue.polling_status == "not_started",
        ).update({"polling_status": "active"})
        db.commit()
    finally:
        db.close()

    if not _env_flag("PHISHPIPELINE_SKIP_TAKEDOWN_TRACKER"):
        asyncio.create_task(takedown_tracker.start())

    if not _env_flag("PHISHPIPELINE_SKIP_CERTSTREAM"):
        asyncio.create_task(certstream_listener.run_listener())


@app.get("/")
def root():
    return {"status": "ok", "service": "phishpipeline-backend"}


@app.get("/api/health")
def health():
    from services.url_transformer import is_loaded

    return {
        "status": "ok",
        "models_loaded": is_loaded(),
        "db": "ok",
    }


@app.delete("/api/demo/reset")
def reset_demo_data(db: Session = Depends(get_db)):
    """DEV ONLY: Wipe all url_queue and report rows for a clean demo start."""
    if os.environ.get("PHISHPIPELINE_ALLOW_RESET") != "1":
        raise HTTPException(
            status_code=403,
            detail="Set PHISHPIPELINE_ALLOW_RESET=1 to enable this endpoint",
        )
    from db.database import Report, RetrainQueue

    db.query(Report).delete()
    db.query(RetrainQueue).delete()
    db.query(URLQueue).delete()
    db.commit()
    return {"status": "ok", "message": "Demo data cleared"}


@app.get("/api/model-info")
def model_info():
    from services.url_transformer import MODEL_NAME, is_loaded

    versions = model_registry.list_versions()
    return {
        "stage1_model": MODEL_NAME,
        "stage2_model": "google/mobilebert-uncased",
        "stage2_threshold": 0.7,
        "current_version": model_registry.current_version,
        "available_versions": len(versions),
        "models_loaded": is_loaded(),
    }
