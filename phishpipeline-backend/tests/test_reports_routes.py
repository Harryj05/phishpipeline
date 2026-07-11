from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import routes.reports as reports_module
from db.database import Base, Report, URLQueue, get_db
from main import app

TEST_DATABASE_URL = "sqlite://"

engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_database(monkeypatch):
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(reports_module, "auto_report", AsyncMock())
    yield
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def seed_url_with_reports():
    db = TestingSessionLocal()
    try:
        url_row = URLQueue(
            url="https://phish.example",
            source="user",
            timestamp=datetime.utcnow(),
            status="classified",
            label="phishing",
            confidence=0.9,
            stage="URL_ONLY",
            reported_at=datetime.utcnow(),
        )
        db.add(url_row)
        db.commit()
        db.refresh(url_row)

        db.add_all(
            [
                Report(
                    url_queue_id=url_row.id,
                    channel="gsb",
                    status="submitted",
                    submitted_at=datetime.utcnow(),
                    response_code=200,
                    response_body="ok",
                ),
                Report(
                    url_queue_id=url_row.id,
                    channel="phishtank",
                    status="failed",
                    submitted_at=datetime.utcnow(),
                    error_message="timeout",
                ),
                Report(
                    url_queue_id=url_row.id,
                    channel="openphish",
                    status="skipped",
                ),
                Report(
                    url_queue_id=url_row.id,
                    channel="registrar",
                    status="submitted",
                    submitted_at=datetime.utcnow(),
                ),
            ]
        )
        db.commit()
        return url_row.id
    finally:
        db.close()


def test_list_reports_groups_by_url_with_channel_statuses(client):
    url_id = seed_url_with_reports()

    response = client.get("/api/reports")

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["page"] == 1
    assert len(data["rows"]) == 1
    assert set(data["summary"].keys()) == {"submitted", "failed", "pending"}
    assert data["summary"]["submitted"] == 2
    assert data["summary"]["failed"] == 1

    entry = data["rows"][0]
    assert entry["url_queue_id"] == url_id
    assert entry["url"] == "https://phish.example"
    assert {k: v["status"] for k, v in entry["channels"].items()} == {
        "gsb": "submitted",
        "phishtank": "failed",
        "openphish": "skipped",
        "registrar": "submitted",
    }
    assert entry["channels"]["phishtank"]["error_message"] == "timeout"
    assert entry["reported_at"] is not None


def test_list_reports_reported_at_comes_from_url_queue_even_if_all_channels_lack_a_timestamp(
    client,
):
    db = TestingSessionLocal()
    try:
        url_row = URLQueue(
            url="https://all-skipped.example",
            source="user",
            timestamp=datetime.utcnow(),
            status="classified",
            label="phishing",
            confidence=0.8,
            stage="URL_ONLY",
            reported_at=datetime.utcnow(),
        )
        db.add(url_row)
        db.commit()
        db.refresh(url_row)

        db.add_all(
            [
                Report(url_queue_id=url_row.id, channel="gsb", status="skipped"),
                Report(url_queue_id=url_row.id, channel="phishtank", status="skipped"),
                Report(url_queue_id=url_row.id, channel="openphish", status="skipped"),
                Report(
                    url_queue_id=url_row.id,
                    channel="registrar",
                    status="failed",
                    error_message="no abuse email found",
                ),
            ]
        )
        db.commit()
        url_id = url_row.id
    finally:
        db.close()

    response = client.get("/api/reports")
    entry = next(
        e for e in response.json()["rows"] if e["url_queue_id"] == url_id
    )

    assert entry["reported_at"] is not None


def test_get_report_detail_returns_all_channel_records(client):
    url_id = seed_url_with_reports()

    response = client.get(f"/api/reports/{url_id}")

    assert response.status_code == 200
    data = response.json()
    assert data["url"] == "https://phish.example"
    assert len(data["reports"]) == 4
    gsb_report = next(r for r in data["reports"] if r["channel"] == "gsb")
    assert gsb_report["status"] == "submitted"
    assert gsb_report["response_code"] == 200


def test_get_report_detail_missing_url_returns_404(client):
    response = client.get("/api/reports/999")
    assert response.status_code == 404


def test_retry_report_queues_background_task(client):
    url_id = seed_url_with_reports()

    response = client.post(f"/api/reports/retry/{url_id}")

    assert response.status_code == 200
    assert response.json() == {"status": "retry_queued", "url_id": url_id}
    reports_module.auto_report.assert_called_once_with("https://phish.example", url_id)


def test_retry_report_missing_url_returns_404(client):
    response = client.post("/api/reports/retry/999")
    assert response.status_code == 404
