from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from db.database import Report, URLQueue, get_db
from services.reporter import auto_report

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("")
def list_reports(
    page: int = 1,
    limit: int = 10,
    status: Optional[str] = None,
    channel: Optional[str] = None,
    db: Session = Depends(get_db),
):
    offset = (page - 1) * limit

    url_ids_query = db.query(Report.url_queue_id).distinct()
    if channel and channel.lower() != "all":
        url_ids_query = url_ids_query.filter(Report.channel == channel.lower())
    if status and status.lower() != "all":
        url_ids_query = url_ids_query.filter(Report.status == status.lower())

    total_ids = url_ids_query.count()
    url_ids = [r[0] for r in url_ids_query.offset(offset).limit(limit).all()]

    results = []
    for uid in url_ids:
        url_row = db.query(URLQueue).filter(URLQueue.id == uid).first()
        if not url_row:
            continue
        channel_reports = (
            db.query(Report).filter(Report.url_queue_id == uid).all()
        )
        channels = {}
        for r in channel_reports:
            channels[r.channel] = {
                "status": r.status,
                "submitted_at": (
                    r.submitted_at.isoformat() if r.submitted_at else None
                ),
                "response_code": r.response_code,
                "response_body": r.response_body,
                "error_message": r.error_message,
            }
        results.append(
            {
                "url_queue_id": uid,
                "url": url_row.url,
                "reported_at": (
                    url_row.reported_at.isoformat()
                    if url_row.reported_at
                    else None
                ),
                "channels": channels,
            }
        )

    results.sort(key=lambda entry: entry["reported_at"] or "", reverse=True)

    submitted = db.query(Report).filter(Report.status == "submitted").count()
    failed = db.query(Report).filter(Report.status == "failed").count()
    pending = db.query(Report).filter(Report.status == "pending").count()

    return {
        "rows": results,
        "total": total_ids,
        "page": page,
        "limit": limit,
        "summary": {
            "submitted": submitted,
            "failed": failed,
            "pending": pending,
        },
    }


@router.get("/{url_queue_id}")
def get_report_detail(url_queue_id: int, db: Session = Depends(get_db)):
    entry = db.query(URLQueue).filter(URLQueue.id == url_queue_id).first()
    if entry is None:
        raise HTTPException(status_code=404, detail="URL not found")

    reports = (
        db.query(Report)
        .filter(Report.url_queue_id == url_queue_id)
        .order_by(Report.id.desc())
        .all()
    )

    return {
        "url_id": entry.id,
        "url": entry.url,
        "reported_at": entry.reported_at,
        "confidence": entry.confidence,
        "attack_category": entry.attack_category,
        "first_seen": entry.timestamp,
        "reports": [
            {
                "channel": report.channel,
                "status": report.status,
                "submitted_at": report.submitted_at,
                "response_code": report.response_code,
                "response_body": report.response_body,
                "error_message": report.error_message,
            }
            for report in reports
        ],
    }


@router.post("/retry/{url_queue_id}")
async def retry_report(
    url_queue_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    entry = db.query(URLQueue).filter(URLQueue.id == url_queue_id).first()
    if entry is None:
        raise HTTPException(status_code=404, detail="URL not found")

    background_tasks.add_task(auto_report, entry.url, entry.id)

    return {"status": "retry_queued", "url_id": entry.id}
