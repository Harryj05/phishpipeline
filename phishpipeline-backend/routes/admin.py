import asyncio
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from db.database import RetrainQueue, URLQueue, get_db
from services.model_registry import model_registry
from services.trainer import ModelTrainer

router = APIRouter(prefix="/api/admin", tags=["admin"])

# NOTE on "false positive" definition: per spec, a False Positive is any row
# an admin labels true_label="clean" (regardless of what the model originally
# predicted) — not strictly (model said phishing AND admin says clean). This
# keeps the retrain-trigger count and /stats false_positives count consistent
# with each other and with the literal spec wording.
FP_RETRAIN_TRIGGER_COUNT = 10
STAGE2_CONFIDENCE_THRESHOLD = 0.7


class LabelRequest(BaseModel):
    id: int
    true_label: str
    labeled_by: str


def _flagged_query(db: Session):
    return db.query(URLQueue).filter(URLQueue.true_label.is_(None)).filter(
        or_(
            URLQueue.confidence < STAGE2_CONFIDENCE_THRESHOLD,
            and_(URLQueue.status == "classified", URLQueue.label == "phishing"),
        )
    )


@router.get("/flagged")
def get_flagged(
    min_confidence: float = 0.0,
    max_confidence: float = 1.0,
    source: str = "all",
    limit: int = 50,
    db: Session = Depends(get_db),
):
    query = _flagged_query(db)

    if min_confidence > 0:
        query = query.filter(URLQueue.confidence >= min_confidence)
    if max_confidence < 1:
        query = query.filter(URLQueue.confidence <= max_confidence)
    if source and source != "all":
        query = query.filter(URLQueue.source == source)

    rows = query.order_by(URLQueue.timestamp.desc()).limit(limit).all()

    return [
        {
            "id": row.id,
            "url": row.url,
            "label": row.label,
            "confidence": row.confidence,
            "stage": row.stage,
            "suspicion_score": row.suspicion_score,
            "timestamp": row.timestamp,
            "source": row.source,
        }
        for row in rows
    ]


def _maybe_trigger_retrain(db: Session) -> None:
    last_retrain = (
        db.query(RetrainQueue).order_by(RetrainQueue.triggered_at.desc()).first()
    )
    last_retrain_at = last_retrain.triggered_at if last_retrain else datetime.min

    fp_count = (
        db.query(URLQueue)
        .filter(URLQueue.true_label == "clean")
        .filter(URLQueue.labeled_at > last_retrain_at)
        .count()
    )

    if fp_count >= FP_RETRAIN_TRIGGER_COUNT:
        db.add(
            RetrainQueue(
                triggered_at=datetime.utcnow(),
                fp_count=fp_count,
                status="pending",
            )
        )
        db.commit()


@router.post("/label")
def label_url(request: LabelRequest, db: Session = Depends(get_db)):
    if request.true_label not in ("phishing", "clean"):
        raise HTTPException(
            status_code=422, detail="true_label must be 'phishing' or 'clean'"
        )

    entry = db.query(URLQueue).filter(URLQueue.id == request.id).first()
    if entry is None:
        raise HTTPException(status_code=404, detail="URL not found")

    entry.true_label = request.true_label
    entry.labeled_by = request.labeled_by
    entry.labeled_at = datetime.utcnow()
    db.commit()
    db.refresh(entry)

    _maybe_trigger_retrain(db)

    return {
        "id": entry.id,
        "true_label": entry.true_label,
        "labeled_by": entry.labeled_by,
        "labeled_at": entry.labeled_at,
    }


@router.get("/stats")
def get_admin_stats(db: Session = Depends(get_db)):
    total_reviewed = (
        db.query(URLQueue).filter(URLQueue.true_label.isnot(None)).count()
    )
    true_positives = (
        db.query(URLQueue).filter(URLQueue.true_label == "phishing").count()
    )
    false_positives = (
        db.query(URLQueue).filter(URLQueue.true_label == "clean").count()
    )
    pending_review = _flagged_query(db).count()

    fp_rate = (
        round(false_positives / total_reviewed * 100, 1)
        if total_reviewed > 0
        else 0.0
    )

    last_retrain = (
        db.query(RetrainQueue).order_by(RetrainQueue.triggered_at.desc()).first()
    )
    last_retrain_triggered_at: Optional[str] = (
        last_retrain.triggered_at.isoformat()
        if last_retrain and last_retrain.triggered_at
        else None
    )

    # FP labels accumulated since the last retrain trigger — this is what
    # gates the "Start Retraining" button in the dashboard.
    fp_count_query = db.query(URLQueue).filter(URLQueue.true_label == "clean")
    if last_retrain is not None:
        fp_count_query = fp_count_query.filter(
            URLQueue.labeled_at > last_retrain.triggered_at
        )
    fp_count = fp_count_query.count()

    return {
        "total_reviewed": total_reviewed,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "pending_review": pending_review,
        "fp_rate": fp_rate,
        "fp_count": fp_count,
        "last_retrain_triggered_at": last_retrain_triggered_at,
    }


@router.post("/retrain")
async def trigger_retrain(db: Session = Depends(get_db)):
    job = (
        db.query(RetrainQueue)
        .filter(RetrainQueue.status == "pending")
        .order_by(RetrainQueue.triggered_at.desc())
        .first()
    )

    if job is None:
        raise HTTPException(
            status_code=400,
            detail="No retraining job queued. Need 10+ False Positive labels first.",
        )

    trainer = ModelTrainer()
    asyncio.create_task(trainer.run_retraining(job.id))

    return {
        "job_id": job.id,
        "status": "started",
        "message": (
            f"Retraining job {job.id} started with {job.fp_count} "
            "false positives."
        ),
    }


@router.get("/retrain/status")
def get_retrain_status(db: Session = Depends(get_db)):
    jobs = db.query(RetrainQueue).order_by(RetrainQueue.id.desc()).all()
    all_versions = model_registry.list_versions()

    results = []
    for job in jobs:
        entry = {
            "id": job.id,
            "status": job.status,
            "triggered_at": job.triggered_at,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "fp_count": job.fp_count,
            "model_version": None,
            "val_f1_url": None,
            "val_f1_html": None,
        }

        if job.status == "complete" and all_versions:
            latest = max(all_versions, key=lambda v: v["version"])
            entry["model_version"] = latest["version"]
            entry["val_f1_url"] = latest.get("val_f1_url")
            entry["val_f1_html"] = latest.get("val_f1_html")

        results.append(entry)

    return results


@router.get("/model-versions")
def list_model_versions():
    versions = sorted(model_registry.list_versions(), key=lambda v: v["version"])
    for version in versions:
        version["current"] = version["version"] == model_registry.current_version
    return versions


@router.post("/model-versions/{version}/rollback")
def rollback_model_version(version: int):
    available_versions = {v["version"] for v in model_registry.list_versions()}
    if version not in available_versions:
        raise HTTPException(
            status_code=404, detail=f"Model version {version} not found"
        )

    model_registry.deploy(version)

    return {"status": "rolled_back", "version": version}
