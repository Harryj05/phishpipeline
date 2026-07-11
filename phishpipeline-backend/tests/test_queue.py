from datetime import datetime

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


def seed_rows():
    db = TestingSessionLocal()
    try:
        db.add_all(
            [
                URLQueue(
                    url="https://phishy-login-verify.xyz",
                    source="certstream",
                    timestamp=datetime.utcnow(),
                    status="classified",
                    label="phishing",
                    confidence=0.95,
                    stage="stub",
                    suspicion_score=85,
                ),
                URLQueue(
                    url="https://example.com",
                    source="user",
                    timestamp=datetime.utcnow(),
                    status="classified",
                    label="benign",
                    confidence=0.9,
                    stage="stub",
                    suspicion_score=5,
                ),
                URLQueue(
                    url="https://newly-registered-domain.com",
                    source="certstream",
                    timestamp=datetime.utcnow(),
                    status="pending",
                    label=None,
                    confidence=None,
                    stage=None,
                    suspicion_score=40,
                ),
            ]
        )
        db.commit()
    finally:
        db.close()


def test_queue_returns_all_rows(client):
    seed_rows()

    response = client.get("/api/queue")

    assert response.status_code == 200
    data = response.json()

    assert len(data) == 3

    urls = {row["url"] for row in data}
    assert urls == {
        "https://phishy-login-verify.xyz",
        "https://example.com",
        "https://newly-registered-domain.com",
    }

    expected_fields = {
        "id",
        "url",
        "source",
        "timestamp",
        "status",
        "label",
        "confidence",
        "stage",
        "suspicion_score",
        "attack_category",
        "reported_at",
        "polling_status",
        "takedown_at",
        "time_to_takedown_mins",
        "true_label",
    }
    for row in data:
        assert set(row.keys()) == expected_fields


def test_queue_phishing_only_filter(client):
    seed_rows()

    response = client.get("/api/queue", params={"phishing_only": True})

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["url"] == "https://phishy-login-verify.xyz"
