"""Multi-channel automated phishing reporting orchestrator."""

import asyncio
import logging
import os
from datetime import datetime

from db.database import Report, SessionLocal, URLQueue
from services.gsb_reporter import report_gsb
from services.openphish_reporter import report_openphish
from services.phishtank_reporter import report_phishtank
from services.registrar_reporter import report_registrar

logger = logging.getLogger(__name__)

AUTO_REPORT_CONFIDENCE_THRESHOLD = float(
    os.environ.get("PHISHPIPELINE_AUTO_REPORT_THRESHOLD", "0.7")
)


async def auto_report(url: str, url_queue_id: int) -> None:
    db = SessionLocal()
    try:
        entry = db.query(URLQueue).filter(URLQueue.id == url_queue_id).first()
        confidence = (entry.confidence if entry else None) or 0.0
        timestamp = entry.timestamp if entry else datetime.utcnow()
    finally:
        db.close()

    results = await asyncio.gather(
        report_gsb(url),
        report_phishtank(url),
        report_openphish(url),
        report_registrar(url, timestamp=timestamp, confidence=confidence),
        return_exceptions=True,
    )

    db = SessionLocal()
    try:
        for result in results:
            if isinstance(result, BaseException):
                logger.error(
                    "Reporter raised an unhandled exception for %s: %s", url, result
                )
                continue

            logger.info("Report result for %s: %s", url, result)

            db.add(
                Report(
                    url_queue_id=url_queue_id,
                    channel=result.get("channel", "unknown"),
                    status=result.get("status", "failed"),
                    submitted_at=datetime.utcnow(),
                    response_code=result.get("response_code"),
                    response_body=result.get("response_body"),
                    error_message=result.get("error_message"),
                )
            )

        entry = db.query(URLQueue).filter(URLQueue.id == url_queue_id).first()
        if entry is not None:
            entry.reported_at = datetime.utcnow()
            # A freshly-reported URL should immediately enter the takedown
            # tracker's polling pool, unless it's already being tracked
            # (taken_down/error) from a prior report/retry cycle.
            if entry.polling_status == "not_started":
                entry.polling_status = "active"

        db.commit()
    finally:
        db.close()
