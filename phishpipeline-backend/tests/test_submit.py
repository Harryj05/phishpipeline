from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import routes.submit as submit_module
from db.database import Base, get_db
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


@pytest.fixture(autouse=True)
def stub_classifier(monkeypatch):
    async def fake_classify(url):
        return {"label": "unknown", "confidence": 0.5, "stage": "stub"}

    monkeypatch.setattr(submit_module, "classify", fake_classify)


@pytest.fixture
def stub_auto_report(monkeypatch):
    mock = AsyncMock()
    monkeypatch.setattr(submit_module, "auto_report", mock)
    return mock


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_submit_url_valid_returns_200_with_expected_fields(client):
    response = client.post(
        "/api/submit-url", json={"url": "https://example.com"}
    )

    assert response.status_code == 200
    data = response.json()
    assert data["url"] == "https://example.com"
    assert data["source"] == "user"
    assert data["label"] == "unknown"
    assert data["confidence"] == 0.5
    assert data["stage"] == "stub"
    assert isinstance(data["id"], int)
    assert "timestamp" in data


def test_submit_url_missing_url_returns_422(client):
    response = client.post("/api/submit-url", json={})

    assert response.status_code == 422


def test_submit_url_non_http_scheme_returns_422(client):
    response = client.post(
        "/api/submit-url", json={"url": "ftp://example.com/file"}
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "Invalid URL format"


def test_submit_url_response_contains_all_expected_fields(client):
    response = client.post(
        "/api/submit-url", json={"url": "http://phishy.example.com"}
    )

    assert response.status_code == 200
    data = response.json()
    expected_fields = {
        "id",
        "url",
        "source",
        "label",
        "confidence",
        "stage",
        "timestamp",
    }
    assert expected_fields.issubset(data.keys())


def test_high_confidence_phishing_triggers_auto_report(
    client, monkeypatch, stub_auto_report
):
    async def fake_phishing_classify(url):
        return {"label": "phishing", "confidence": 0.92, "stage": "URL_ONLY"}

    monkeypatch.setattr(submit_module, "classify", fake_phishing_classify)

    response = client.post(
        "/api/submit-url", json={"url": "https://evil-phish.example"}
    )

    assert response.status_code == 200
    stub_auto_report.assert_called_once()
    call_args = stub_auto_report.call_args[0]
    assert call_args[0] == "https://evil-phish.example"
    assert call_args[1] == response.json()["id"]


def test_low_confidence_phishing_does_not_trigger_auto_report(
    client, monkeypatch, stub_auto_report
):
    async def fake_low_confidence_classify(url):
        return {"label": "phishing", "confidence": 0.5, "stage": "URL_ONLY"}

    monkeypatch.setattr(submit_module, "classify", fake_low_confidence_classify)

    response = client.post(
        "/api/submit-url", json={"url": "https://maybe-phish.example"}
    )

    assert response.status_code == 200
    stub_auto_report.assert_not_called()


def test_clean_label_does_not_trigger_auto_report(client, stub_auto_report):
    response = client.post(
        "/api/submit-url", json={"url": "https://clean-site.example"}
    )

    assert response.status_code == 200
    stub_auto_report.assert_not_called()
