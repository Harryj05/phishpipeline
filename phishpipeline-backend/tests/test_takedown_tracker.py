import asyncio
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import services.takedown_tracker as tracker_module
from db.database import Base, URLQueue

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
    monkeypatch.setattr(tracker_module, "SessionLocal", TestingSessionLocal)
    yield
    Base.metadata.drop_all(bind=engine)


def seed_row(**overrides):
    defaults = dict(
        url="https://phish.example",
        source="user",
        timestamp=datetime.utcnow() - timedelta(minutes=45),
        status="classified",
        label="phishing",
        confidence=0.95,
        stage="URL_ONLY",
        reported_at=datetime.utcnow(),
        polling_status="active",
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


def get_row(row_id):
    db = TestingSessionLocal()
    try:
        return db.query(URLQueue).filter(URLQueue.id == row_id).first()
    finally:
        db.close()


def test_check_url_returns_taken_down_on_4xx_status():
    tracker = tracker_module.TakedownTracker()
    row = SimpleNamespace(url="https://phish.example", timestamp=datetime.utcnow())

    mock_response = httpx.Response(404, request=httpx.Request("GET", row.url))

    async def fake_get(self, url, **kwargs):
        return mock_response

    with patch.object(httpx.AsyncClient, "get", new=fake_get):
        status = asyncio.run(tracker.check_url(row))

    assert status == "taken_down"


def test_check_url_returns_taken_down_when_redirected_to_safe_domain():
    tracker = tracker_module.TakedownTracker()
    row = SimpleNamespace(url="https://phish.example", timestamp=datetime.utcnow())

    # simulate the client having followed a redirect to a registrar parking page
    mock_response = httpx.Response(
        200,
        request=httpx.Request("GET", "https://parking.godaddy.com/x"),
    )

    async def fake_get(self, url, **kwargs):
        return mock_response

    with patch.object(httpx.AsyncClient, "get", new=fake_get):
        status = asyncio.run(tracker.check_url(row))

    assert status == "taken_down"


def test_check_url_returns_active_for_normal_200_response():
    tracker = tracker_module.TakedownTracker()
    row = SimpleNamespace(url="https://still-live.example", timestamp=datetime.utcnow())

    mock_response = httpx.Response(200, request=httpx.Request("GET", row.url))

    async def fake_get(self, url, **kwargs):
        return mock_response

    with patch.object(httpx.AsyncClient, "get", new=fake_get):
        status = asyncio.run(tracker.check_url(row))

    assert status == "active"


def test_check_url_returns_taken_down_on_connect_error():
    tracker = tracker_module.TakedownTracker()
    row = SimpleNamespace(url="https://dead-domain.example", timestamp=datetime.utcnow())

    async def fake_get(self, url, **kwargs):
        raise httpx.ConnectError("connection refused")

    with patch.object(httpx.AsyncClient, "get", new=fake_get):
        status = asyncio.run(tracker.check_url(row))

    assert status == "taken_down"


def test_check_url_returns_error_on_unexpected_exception():
    tracker = tracker_module.TakedownTracker()
    row = SimpleNamespace(url="https://weird.example", timestamp=datetime.utcnow())

    async def fake_get(self, url, **kwargs):
        raise ValueError("something unexpected")

    with patch.object(httpx.AsyncClient, "get", new=fake_get):
        status = asyncio.run(tracker.check_url(row))

    assert status == "error"


def test_mark_taken_down_updates_row_and_computes_minutes():
    row_id = seed_row(timestamp=datetime.utcnow() - timedelta(minutes=42))
    tracker = tracker_module.TakedownTracker()
    row = get_row(row_id)

    asyncio.run(tracker.mark_taken_down(row))

    updated = get_row(row_id)
    assert updated.polling_status == "taken_down"
    assert updated.takedown_at is not None
    assert updated.time_to_takedown_mins in (41, 42, 43)  # allow small timing drift


def test_poll_all_active_only_polls_active_reported_phishing_rows():
    active_id = seed_row(url="https://active-one.example")
    seed_row(url="https://not-reported.example", reported_at=None)
    seed_row(url="https://not-phishing.example", label="clean", reported_at=datetime.utcnow())
    seed_row(url="https://already-down.example", polling_status="taken_down")

    tracker = tracker_module.TakedownTracker()
    checked_urls = []

    async def fake_check_url(self, row):
        checked_urls.append(row.url)
        return "active"

    with patch.object(tracker_module.TakedownTracker, "check_url", new=fake_check_url):
        asyncio.run(tracker.poll_all_active())

    assert checked_urls == ["https://active-one.example"]

    updated = get_row(active_id)
    assert updated.last_polled_at is not None
    assert updated.polling_status == "active"


def test_poll_all_active_marks_taken_down_rows():
    row_id = seed_row(url="https://goes-down.example")
    tracker = tracker_module.TakedownTracker()

    async def fake_check_url(self, row):
        return "taken_down"

    with patch.object(tracker_module.TakedownTracker, "check_url", new=fake_check_url):
        asyncio.run(tracker.poll_all_active())

    updated = get_row(row_id)
    assert updated.polling_status == "taken_down"
    assert updated.takedown_at is not None
    assert updated.time_to_takedown_mins is not None
