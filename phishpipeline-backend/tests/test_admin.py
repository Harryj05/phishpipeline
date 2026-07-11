from datetime import datetime
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import routes.admin as admin_module
from db.database import Base, RetrainQueue, URLQueue, get_db
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


@pytest.fixture
def stub_trainer(monkeypatch):
    """Prevent POST /api/admin/retrain from launching a real training run."""
    mock_run_retraining = AsyncMock()
    monkeypatch.setattr(
        admin_module.ModelTrainer, "run_retraining", mock_run_retraining
    )
    return mock_run_retraining


def seed_row(**overrides):
    defaults = dict(
        url="https://example.com",
        source="user",
        timestamp=datetime.utcnow(),
        status="classified",
        label="clean",
        confidence=0.5,
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


def test_flagged_includes_low_confidence_and_unreviewed_phishing(client):
    low_conf_id = seed_row(
        url="https://low-conf.example", confidence=0.4, label="clean"
    )
    high_conf_phish_id = seed_row(
        url="https://phish.example", confidence=0.95, label="phishing"
    )
    seed_row(
        url="https://already-reviewed.example",
        confidence=0.99,
        label="phishing",
        true_label="phishing",
        labeled_by="admin",
        labeled_at=datetime.utcnow(),
    )

    response = client.get("/api/admin/flagged")

    assert response.status_code == 200
    ids = {row["id"] for row in response.json()}
    assert ids == {low_conf_id, high_conf_phish_id}


def test_flagged_response_has_expected_fields(client):
    seed_row(confidence=0.3)

    response = client.get("/api/admin/flagged")
    row = response.json()[0]

    assert set(row.keys()) == {
        "id",
        "url",
        "label",
        "confidence",
        "stage",
        "suspicion_score",
        "timestamp",
        "source",
    }


def test_label_url_updates_row_and_removes_from_flagged(client):
    row_id = seed_row(confidence=0.3)

    response = client.post(
        "/api/admin/label",
        json={"id": row_id, "true_label": "clean", "labeled_by": "analyst1"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["true_label"] == "clean"
    assert data["labeled_by"] == "analyst1"

    flagged = client.get("/api/admin/flagged").json()
    assert row_id not in {row["id"] for row in flagged}


def test_label_invalid_true_label_returns_422(client):
    row_id = seed_row(confidence=0.3)

    response = client.post(
        "/api/admin/label",
        json={"id": row_id, "true_label": "maybe", "labeled_by": "analyst1"},
    )

    assert response.status_code == 422


def test_label_missing_row_returns_404(client):
    response = client.post(
        "/api/admin/label",
        json={"id": 999, "true_label": "clean", "labeled_by": "analyst1"},
    )

    assert response.status_code == 404


def test_stats_counts_and_fp_rate(client):
    tp_id = seed_row(confidence=0.3, label="phishing")
    fp_id = seed_row(confidence=0.3, label="phishing")

    client.post(
        "/api/admin/label",
        json={"id": tp_id, "true_label": "phishing", "labeled_by": "a"},
    )
    client.post(
        "/api/admin/label",
        json={"id": fp_id, "true_label": "clean", "labeled_by": "a"},
    )

    response = client.get("/api/admin/stats")
    data = response.json()

    assert data["total_reviewed"] == 2
    assert data["true_positives"] == 1
    assert data["false_positives"] == 1
    assert data["fp_rate"] == 50.0
    assert data["fp_count"] == 1
    assert data["last_retrain_triggered_at"] is None


def test_ten_false_positives_triggers_retrain(client):
    for i in range(10):
        row_id = seed_row(url=f"https://fp-{i}.example", confidence=0.3)
        client.post(
            "/api/admin/label",
            json={"id": row_id, "true_label": "clean", "labeled_by": "a"},
        )

    stats = client.get("/api/admin/stats").json()
    assert stats["last_retrain_triggered_at"] is not None

    db = TestingSessionLocal()
    try:
        retrain_rows = db.query(RetrainQueue).all()
        assert len(retrain_rows) == 1
        assert retrain_rows[0].fp_count == 10
        assert retrain_rows[0].status == "pending"
    finally:
        db.close()


def seed_retrain_job(**overrides):
    defaults = dict(
        triggered_at=datetime.utcnow(),
        fp_count=10,
        status="pending",
    )
    defaults.update(overrides)
    db = TestingSessionLocal()
    try:
        job = RetrainQueue(**defaults)
        db.add(job)
        db.commit()
        db.refresh(job)
        return job.id
    finally:
        db.close()


def test_trigger_retrain_with_no_pending_job_returns_400(client, stub_trainer):
    response = client.post("/api/admin/retrain")

    assert response.status_code == 400
    assert "10+ False Positive" in response.json()["detail"]
    stub_trainer.assert_not_called()


def test_trigger_retrain_starts_background_task(client, stub_trainer):
    job_id = seed_retrain_job()

    response = client.post("/api/admin/retrain")

    assert response.status_code == 200
    data = response.json()
    assert data["job_id"] == job_id
    assert data["status"] == "started"
    assert "10" in data["message"]


def test_retrain_status_lists_jobs(client):
    job_id = seed_retrain_job(status="running", started_at=datetime.utcnow())

    response = client.get("/api/admin/retrain/status")

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["id"] == job_id
    assert data[0]["status"] == "running"
    assert data[0]["model_version"] is None


def test_retrain_status_includes_model_version_when_complete(client, monkeypatch):
    seed_retrain_job(status="complete", completed_at=datetime.utcnow())

    monkeypatch.setattr(
        admin_module.model_registry,
        "list_versions",
        lambda: [{"version": 1, "val_f1_url": 0.9, "val_f1_html": 0.85}],
    )

    response = client.get("/api/admin/retrain/status")
    data = response.json()

    assert data[0]["model_version"] == 1
    assert data[0]["val_f1_url"] == 0.9
    assert data[0]["val_f1_html"] == 0.85


def test_list_model_versions_returns_sorted_versions(client, monkeypatch):
    monkeypatch.setattr(
        admin_module.model_registry,
        "list_versions",
        lambda: [{"version": 2}, {"version": 1}],
    )
    monkeypatch.setattr(admin_module.model_registry, "current_version", 2)

    response = client.get("/api/admin/model-versions")

    assert response.status_code == 200
    data = response.json()
    assert [v["version"] for v in data] == [1, 2]
    assert [v["current"] for v in data] == [False, True]


def test_rollback_to_existing_version_calls_deploy(client, monkeypatch):
    monkeypatch.setattr(
        admin_module.model_registry,
        "list_versions",
        lambda: [{"version": 1}, {"version": 2}],
    )
    deploy_calls = []
    monkeypatch.setattr(
        admin_module.model_registry, "deploy", lambda v: deploy_calls.append(v)
    )

    response = client.post("/api/admin/model-versions/1/rollback")

    assert response.status_code == 200
    assert response.json() == {"status": "rolled_back", "version": 1}
    assert deploy_calls == [1]


def test_rollback_to_nonexistent_version_returns_404(client, monkeypatch):
    monkeypatch.setattr(
        admin_module.model_registry, "list_versions", lambda: [{"version": 1}]
    )

    response = client.post("/api/admin/model-versions/99/rollback")

    assert response.status_code == 404
