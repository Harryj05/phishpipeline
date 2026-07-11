import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import services.reporter as reporter_module
from db.database import Base, Report, URLQueue

TEST_DATABASE_URL = "sqlite://"

engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def setup_database(monkeypatch):
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(reporter_module, "SessionLocal", TestingSessionLocal)
    yield
    Base.metadata.drop_all(bind=engine)


def seed_url(**overrides):
    defaults = dict(
        url="https://phish.example",
        source="user",
        timestamp=datetime.utcnow(),
        status="classified",
        label="phishing",
        confidence=0.95,
        stage="URL_ONLY",
    )
    defaults.update(overrides)
    db = TestingSessionLocal()
    try:
        row = URLQueue(**defaults)
        db.add(row)
        db.commit()
        db.refresh(row)
        return row.id
    finally:
        db.close()


def test_auto_report_inserts_a_row_per_channel_and_sets_reported_at():
    url_id = seed_url()

    with patch.object(
        reporter_module,
        "report_gsb",
        new=AsyncMock(
            return_value={"channel": "gsb", "status": "submitted", "response_code": 200}
        ),
    ), patch.object(
        reporter_module,
        "report_phishtank",
        new=AsyncMock(
            return_value={"channel": "phishtank", "status": "skipped", "phishtank_id": None}
        ),
    ), patch.object(
        reporter_module,
        "report_openphish",
        new=AsyncMock(
            return_value={"channel": "openphish", "status": "failed", "error_message": "boom"}
        ),
    ), patch.object(
        reporter_module,
        "report_registrar",
        new=AsyncMock(
            return_value={
                "channel": "registrar",
                "status": "submitted",
                "registrar": "Fake Registrar",
            }
        ),
    ):
        asyncio.run(reporter_module.auto_report("https://phish.example", url_id))

    db = TestingSessionLocal()
    try:
        reports = db.query(Report).filter(Report.url_queue_id == url_id).all()
        channels = {report.channel: report.status for report in reports}
        assert channels == {
            "gsb": "submitted",
            "phishtank": "skipped",
            "openphish": "failed",
            "registrar": "submitted",
        }

        entry = db.query(URLQueue).filter(URLQueue.id == url_id).first()
        assert entry.reported_at is not None
        assert entry.polling_status == "active"
    finally:
        db.close()


def test_auto_report_does_not_reactivate_a_row_already_taken_down():
    url_id = seed_url(polling_status="taken_down")

    with patch.object(
        reporter_module, "report_gsb", new=AsyncMock(return_value={"channel": "gsb", "status": "submitted"})
    ), patch.object(
        reporter_module, "report_phishtank", new=AsyncMock(return_value={"channel": "phishtank", "status": "submitted"})
    ), patch.object(
        reporter_module, "report_openphish", new=AsyncMock(return_value={"channel": "openphish", "status": "submitted"})
    ), patch.object(
        reporter_module, "report_registrar", new=AsyncMock(return_value={"channel": "registrar", "status": "submitted"})
    ):
        asyncio.run(reporter_module.auto_report("https://phish.example", url_id))

    db = TestingSessionLocal()
    try:
        entry = db.query(URLQueue).filter(URLQueue.id == url_id).first()
        assert entry.polling_status == "taken_down"
    finally:
        db.close()


def test_auto_report_survives_a_reporter_raising_an_exception():
    url_id = seed_url()

    async def boom(*args, **kwargs):
        raise RuntimeError("network exploded")

    with patch.object(reporter_module, "report_gsb", new=boom), patch.object(
        reporter_module,
        "report_phishtank",
        new=AsyncMock(return_value={"channel": "phishtank", "status": "submitted"}),
    ), patch.object(
        reporter_module,
        "report_openphish",
        new=AsyncMock(return_value={"channel": "openphish", "status": "submitted"}),
    ), patch.object(
        reporter_module,
        "report_registrar",
        new=AsyncMock(return_value={"channel": "registrar", "status": "submitted"}),
    ):
        # must not raise
        asyncio.run(reporter_module.auto_report("https://phish.example", url_id))

    db = TestingSessionLocal()
    try:
        reports = db.query(Report).filter(Report.url_queue_id == url_id).all()
        # only the 3 successful reporters produced rows; gsb's exception was swallowed
        assert len(reports) == 3
    finally:
        db.close()
