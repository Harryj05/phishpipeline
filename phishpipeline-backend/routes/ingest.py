from datetime import datetime, timedelta
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db.database import URLQueue, get_db
from models.url_entry import URLEntry
from services.classifier import classify
from services.reporter import AUTO_REPORT_CONFIDENCE_THRESHOLD, auto_report

router = APIRouter(tags=["ingest"])

# Suspicion boundary shared with the dashboard: scores above this are
# phishing-level, at or below are benign-leaning.
SUSPICION_PHISHING_THRESHOLD = 35


class IngestRequest(BaseModel):
    url: str
    source: str


class IngestDomainRequest(BaseModel):
    url: str
    source: str = "certstream"
    suspicion_score: Optional[int] = None


@router.post("/api/ingest-domain")
async def ingest_domain_api(
    request: IngestDomainRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    url = request.url
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"https://{url}"
        parsed = urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(status_code=422, detail="Invalid URL format")

    entry = URLQueue(
        url=url,
        source="certstream",
        timestamp=datetime.utcnow(),
        status="pending",
        suspicion_score=request.suspicion_score,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    classification = await classify(url)

    entry.label = classification["label"]
    entry.confidence = classification["confidence"]
    entry.stage = classification["stage"]
    entry.attack_category = classification.get("attack_category")
    entry.status = "classified"

    # For certstream-sourced domains the URL-feature suspicion score is
    # authoritative for the final verdict: > 35 means phishing-level,
    # <= 35 means benign-leaning. The transformer model over-predicts
    # phishing on bare newly-registered domains (no path, no HTML), so
    # its verdict alone would label nearly the whole CT feed phishing.
    if entry.suspicion_score is not None:
        score_says_phishing = entry.suspicion_score > SUSPICION_PHISHING_THRESHOLD
        model_says_phishing = classification["label"] == "phishing"
        if score_says_phishing != model_says_phishing:
            entry.label = "phishing" if score_says_phishing else "clean"
            entry.confidence = (
                entry.suspicion_score / 100
                if score_says_phishing
                else 1 - entry.suspicion_score / 100
            )

    db.commit()
    db.refresh(entry)

    if (
        entry.label == "phishing"
        and (entry.confidence or 0) >= AUTO_REPORT_CONFIDENCE_THRESHOLD
    ):
        background_tasks.add_task(auto_report, entry.url, entry.id)

    return {
        "id": entry.id,
        "url": entry.url,
        "source": entry.source,
        "label": entry.label,
        "confidence": entry.confidence,
        "stage": entry.stage,
        "timestamp": entry.timestamp,
        "suspicion_score": entry.suspicion_score,
    }


@router.get("/api/queue")
def get_queue(
    source: Optional[str] = None,
    status: Optional[str] = None,
    label: Optional[str] = None,
    min_score: Optional[int] = None,
    phishing_only: bool = False,
    high_score_only: bool = False,
    hide_wildcards: bool = False,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    query = db.query(URLQueue).order_by(URLQueue.timestamp.desc())

    if source and source != "all":
        query = query.filter(URLQueue.source == source)
    if status:
        query = query.filter(URLQueue.status == status)
    if phishing_only or label == "phishing":
        query = query.filter(URLQueue.label == "phishing")
    if high_score_only:
        query = query.filter(URLQueue.suspicion_score >= 70)
    if hide_wildcards:
        query = query.filter(~URLQueue.url.like("%*%"))
    if min_score is not None:
        query = query.filter(
            (URLQueue.suspicion_score >= min_score)
            | (URLQueue.suspicion_score.is_(None))
        )

    rows = query.limit(limit).all()

    return [
        {
            "id": r.id,
            "url": r.url,
            "source": r.source,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "status": r.status,
            "label": r.label,
            "confidence": r.confidence,
            "stage": r.stage,
            "suspicion_score": r.suspicion_score,
            "attack_category": r.attack_category,
            "reported_at": r.reported_at.isoformat() if r.reported_at else None,
            "polling_status": r.polling_status,
            "takedown_at": r.takedown_at.isoformat() if r.takedown_at else None,
            "time_to_takedown_mins": r.time_to_takedown_mins,
            "true_label": r.true_label,
        }
        for r in rows
    ]


@router.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    ten_min_ago = datetime.utcnow() - timedelta(minutes=10)
    recent = db.query(URLQueue).filter(URLQueue.timestamp >= ten_min_ago).all()
    total = db.query(URLQueue).count()

    return {
        "domainsScanned": len(recent),
        "phishingCount": sum(1 for r in recent if r.label == "phishing"),
        "queuedCount": sum(1 for r in recent if r.status == "pending"),
        "cleanCount": sum(
            1 for r in recent if r.status == "classified" and r.label != "phishing"
        ),
        "totalAllTime": total,
    }


@router.post("/ingest/", response_model=URLEntry)
def ingest_url(request: IngestRequest, db: Session = Depends(get_db)):
    entry = URLQueue(
        url=request.url,
        source=request.source,
        timestamp=datetime.utcnow(),
        status="pending",
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    return entry


@router.post("/ingest/batch", response_model=List[URLEntry])
def ingest_urls(requests: List[IngestRequest], db: Session = Depends(get_db)):
    entries = [
        URLQueue(
            url=request.url,
            source=request.source,
            timestamp=datetime.utcnow(),
            status="pending",
        )
        for request in requests
    ]
    db.add_all(entries)
    db.commit()
    for entry in entries:
        db.refresh(entry)

    return entries


@router.get("/ingest/pending", response_model=List[URLEntry])
def list_pending(db: Session = Depends(get_db)):
    return (
        db.query(URLQueue)
        .filter(URLQueue.status == "pending")
        .order_by(URLQueue.id.desc())
        .all()
    )
