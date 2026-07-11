from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from db.database import Base, URLQueue, get_db
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
def setup_database():
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def seed_row(**overrides):
    defaults = dict(
        url="https://phish.example",
        source="user",
        timestamp=datetime.utcnow(),
        status="classified",
        label="phishing",
        confidence=0.9,
        stage="URL_ONLY",
        reported_at=datetime.utcnow(),
        polling_status="active",
        attack_category="regular",
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


def test_takedown_overall_stats(client):
    seed_row(
        polling_status="taken_down",
        time_to_takedown_mins=60,
        attack_category="js_evasion",
    )
    seed_row(
        polling_status="taken_down",
        time_to_takedown_mins=30,
        attack_category="regular",
    )
    seed_row(polling_status="active", attack_category="regular")

    response = client.get("/api/analytics/takedown")

    assert response.status_code == 200
    data = response.json()

    assert data["overall"]["total_reported"] == 3
    assert data["overall"]["total_taken_down"] == 2
    assert data["overall"]["avg_time_to_takedown_mins"] == 45.0
    assert round(data["overall"]["takedown_rate_percent"], 2) == round(2 / 3 * 100, 2)


def test_takedown_by_category_breakdown(client):
    seed_row(
        attack_category="js_evasion",
        polling_status="taken_down",
        time_to_takedown_mins=20,
    )
    seed_row(attack_category="js_evasion", polling_status="active")
    seed_row(attack_category="clickjacking", polling_status="active")

    response = client.get("/api/analytics/takedown")
    by_category = response.json()["by_category"]

    assert set(by_category.keys()) == {
        "regular",
        "js_evasion",
        "clickjacking",
        "dom_cloaking",
        "text_encoding",
    }
    assert by_category["js_evasion"]["count"] == 2
    assert by_category["js_evasion"]["taken_down"] == 1
    assert by_category["js_evasion"]["avg_mins"] == 20.0
    assert by_category["clickjacking"]["count"] == 1
    assert by_category["regular"]["count"] == 0


def test_takedown_timeline_has_30_days(client):
    seed_row()

    response = client.get("/api/analytics/takedown")
    timeline = response.json()["timeline"]

    assert len(timeline) == 30
    today = datetime.utcnow().date().isoformat()
    assert timeline[-1]["date"] == today
    assert timeline[-1]["reported"] == 1


def test_takedown_live_returns_tracked_rows(client):
    row_id = seed_row(
        polling_status="active",
        last_polled_at=datetime.utcnow() - timedelta(minutes=5),
    )
    # not reported yet -- should be excluded
    seed_row(url="https://not-reported.example", reported_at=None)

    response = client.get("/api/analytics/takedown/live")

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["id"] == row_id
    assert data[0]["polling_status"] == "active"
    assert data[0]["last_polled_at"] is not None
