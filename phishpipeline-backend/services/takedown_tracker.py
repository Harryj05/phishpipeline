"""Background service that polls reported phishing URLs and records when
they go offline (takedown tracking)."""

import asyncio
import logging
import socket
from datetime import datetime
from types import SimpleNamespace
from urllib.parse import urlparse

import httpx

from db.database import SessionLocal, URLQueue

logger = logging.getLogger(__name__)

SAFE_PARKING_DOMAINS = ["google.com", "microsoft.com", "godaddy.com", "namecheap.com"]


class TakedownTracker:
    POLL_INTERVAL = 1800  # 30 minutes
    BATCH_SIZE = 20
    REQUEST_TIMEOUT_SECONDS = 10

    async def start(self):
        while True:
            try:
                await self.poll_all_active()
            except Exception as exc:
                logger.error("Takedown tracker poll cycle failed: %s", exc)
            await asyncio.sleep(self.POLL_INTERVAL)

    async def poll_all_active(self):
        db = SessionLocal()
        try:
            rows = (
                db.query(URLQueue)
                .filter(URLQueue.label == "phishing")
                .filter(URLQueue.polling_status == "active")
                .filter(URLQueue.reported_at.isnot(None))
                .all()
            )
            # Snapshot the fields we need so we can safely use them after
            # this session closes (each row gets its own short-lived
            # session later, since they're checked concurrently).
            row_snapshots = [
                SimpleNamespace(id=row.id, url=row.url, timestamp=row.timestamp)
                for row in rows
            ]
        finally:
            db.close()

        for i in range(0, len(row_snapshots), self.BATCH_SIZE):
            batch = row_snapshots[i : i + self.BATCH_SIZE]
            await asyncio.gather(*(self._process_row(row) for row in batch))

    async def _process_row(self, row) -> None:
        status = await self.check_url(row)

        db = SessionLocal()
        try:
            db_row = db.query(URLQueue).filter(URLQueue.id == row.id).first()
            if db_row is None:
                return
            db_row.last_polled_at = datetime.utcnow()
            if status == "error":
                db_row.polling_status = "error"
            elif status == "active":
                db_row.polling_status = "active"
            db.commit()
        finally:
            db.close()

        if status == "taken_down":
            await self.mark_taken_down(row)

    async def check_url(self, row) -> str:
        try:
            async with httpx.AsyncClient(
                timeout=self.REQUEST_TIMEOUT_SECONDS, follow_redirects=True
            ) as client:
                response = await client.get(row.url)

                if response.status_code >= 400:
                    return "taken_down"

                final_domain = urlparse(str(response.url)).netloc
                if any(
                    safe in final_domain for safe in SAFE_PARKING_DOMAINS
                ):
                    return "taken_down"

                return "active"
        except (httpx.ConnectError, httpx.TimeoutException, socket.gaierror):
            # DNS failure / connection refused / timeout = the site is down
            return "taken_down"
        except Exception as exc:
            logger.error("Error checking %s: %s", row.url, exc)
            return "error"

    async def mark_taken_down(self, row) -> None:
        mins = (datetime.utcnow() - row.timestamp).total_seconds() / 60

        db = SessionLocal()
        try:
            db_row = db.query(URLQueue).filter(URLQueue.id == row.id).first()
            if db_row is None:
                return
            db_row.polling_status = "taken_down"
            db_row.takedown_at = datetime.utcnow()
            db_row.time_to_takedown_mins = round(mins)
            db.commit()
        finally:
            db.close()

        logger.info("TAKEDOWN: %s after %.0f min", row.url, mins)
