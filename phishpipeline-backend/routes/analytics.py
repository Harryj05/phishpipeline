from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from db.database import URLQueue, get_db

router = APIRouter(prefix="/api/analytics", tags=["analytics"])

ATTACK_CATEGORIES = [
    "regular",
    "js_evasion",
    "clickjacking",
    "dom_cloaking",
    "text_encoding",
]

TIMELINE_DAYS = 30


def _avg(values: list) -> float:
    return round(sum(values) / len(values), 2) if values else 0.0


@router.get("/takedown")
def get_takedown_analytics(db: Session = Depends(get_db)):
    reported_rows = (
        db.query(URLQueue)
        .filter(URLQueue.label == "phishing")
        .filter(URLQueue.reported_at.isnot(None))
        .all()
    )

    total_reported = len(reported_rows)
    taken_down_rows = [r for r in reported_rows if r.polling_status == "taken_down"]
    total_taken_down = len(taken_down_rows)

    ttd_values = [
        r.time_to_takedown_mins
        for r in taken_down_rows
        if r.time_to_takedown_mins is not None
    ]
    takedown_rate = (
        (total_taken_down / total_reported * 100) if total_reported else 0.0
    )

    def _normalize_category(value) -> str:
        # Legacy rows carry "unknown" (or NULL); anything not in the known
        # taxonomy counts as "regular" so it is never dropped from charts.
        return value if value in ATTACK_CATEGORIES else "regular"

    by_category = {}
    for category in ATTACK_CATEGORIES:
        category_rows = [
            r
            for r in reported_rows
            if _normalize_category(r.attack_category) == category
        ]
        category_taken_down = [
            r for r in category_rows if r.polling_status == "taken_down"
        ]
        category_ttd_values = [
            r.time_to_takedown_mins
            for r in category_taken_down
            if r.time_to_takedown_mins is not None
        ]
        by_category[category] = {
            "count": len(category_rows),
            "avg_mins": _avg(category_ttd_values),
            "taken_down": len(category_taken_down),
        }

    today = datetime.utcnow().date()
    timeline = []
    for days_ago in range(TIMELINE_DAYS - 1, -1, -1):
        day = today - timedelta(days=days_ago)
        day_reported = [
            r for r in reported_rows if r.reported_at and r.reported_at.date() == day
        ]
        day_taken_down = [r for r in day_reported if r.polling_status == "taken_down"]
        day_ttd_values = [
            r.time_to_takedown_mins
            for r in day_taken_down
            if r.time_to_takedown_mins is not None
        ]
        timeline.append(
            {
                "date": day.isoformat(),
                "reported": len(day_reported),
                "taken_down": len(day_taken_down),
                "avg_mins": _avg(day_ttd_values),
            }
        )

    return {
        "overall": {
            "total_reported": total_reported,
            "total_taken_down": total_taken_down,
            "avg_time_to_takedown_mins": _avg(ttd_values),
            "takedown_rate_percent": round(takedown_rate, 2),
        },
        "by_category": by_category,
        "timeline": timeline,
    }


@router.get("/takedown/live")
def get_takedown_live(db: Session = Depends(get_db)):
    rows = (
        db.query(URLQueue)
        .filter(URLQueue.label == "phishing")
        .filter(URLQueue.reported_at.isnot(None))
        .filter(URLQueue.polling_status.in_(["active", "taken_down", "error"]))
        .order_by(URLQueue.last_polled_at.desc().nullsfirst())
        .limit(50)
        .all()
    )

    return [
        {
            "id": row.id,
            "url": row.url,
            "attack_category": (
                row.attack_category
                if row.attack_category in ATTACK_CATEGORIES
                else "regular"
            ),
            "reported_at": (
                row.reported_at.isoformat() if row.reported_at else None
            ),
            "last_polled_at": (
                row.last_polled_at.isoformat() if row.last_polled_at else None
            ),
            "polling_status": row.polling_status,
            "takedown_at": (
                row.takedown_at.isoformat() if row.takedown_at else None
            ),
            "time_to_takedown_mins": row.time_to_takedown_mins,
        }
        for row in rows
    ]
