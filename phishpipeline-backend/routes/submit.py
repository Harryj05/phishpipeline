from datetime import datetime
from typing import List
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db.database import URLQueue, get_db
from models.url_entry import URLEntry
from services.classifier import classify
from services.reporter import AUTO_REPORT_CONFIDENCE_THRESHOLD, auto_report

router = APIRouter(tags=["submit"])


class SubmitRequest(BaseModel):
    url: str
    source: str = "manual"


class SubmitUrlRequest(BaseModel):
    url: str


@router.post("/api/submit-url")
async def submit_url_api(
    request: SubmitUrlRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    parsed = urlparse(request.url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(status_code=422, detail="Invalid URL format")

    entry = URLQueue(
        url=request.url,
        source="user",
        timestamp=datetime.utcnow(),
        status="pending",
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    classification = await classify(request.url)

    entry.label = classification["label"]
    entry.confidence = classification["confidence"]
    entry.stage = classification["stage"]
    entry.attack_category = classification.get("attack_category")
    entry.status = "classified"
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
        "adversarial_flags": classification.get("adversarial_flags", []),
    }


@router.post("/submit/", response_model=URLEntry)
async def submit_url(
    request: SubmitRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    classification = await classify(request.url)

    entry = URLQueue(
        url=request.url,
        source=request.source,
        timestamp=datetime.utcnow(),
        status="classified",
        label=classification["label"],
        confidence=classification["confidence"],
        stage=classification["stage"],
        attack_category=classification.get("attack_category"),
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    if (
        entry.label == "phishing"
        and (entry.confidence or 0) >= AUTO_REPORT_CONFIDENCE_THRESHOLD
    ):
        background_tasks.add_task(auto_report, entry.url, entry.id)

    return entry


@router.get("/submit/", response_model=List[URLEntry])
def list_submissions(db: Session = Depends(get_db)):
    return db.query(URLQueue).order_by(URLQueue.id.desc()).all()
