import asyncio
import json
from datetime import datetime
from unittest.mock import patch

import pandas as pd
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import services.trainer as trainer_module
from db.database import Base, RetrainQueue, URLQueue
from services.model_registry import ModelRegistry
from services.trainer import ModelTrainer

TEST_DATABASE_URL = "sqlite://"

engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def setup_database(monkeypatch, tmp_path):
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(trainer_module, "SessionLocal", TestingSessionLocal)
    monkeypatch.setattr(trainer_module, "VERSION_DIR", str(tmp_path))
    ModelRegistry._instance = None
    yield tmp_path
    Base.metadata.drop_all(bind=engine)
    ModelRegistry._instance = None


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


def seed_labeled_url(**overrides):
    defaults = dict(
        url="https://phish.example",
        source="user",
        timestamp=datetime.utcnow(),
        status="classified",
        label="phishing",
        confidence=0.9,
        true_label="phishing",
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


def get_job(job_id):
    db = TestingSessionLocal()
    try:
        return db.query(RetrainQueue).filter(RetrainQueue.id == job_id).first()
    finally:
        db.close()


def test_run_retraining_happy_path_completes_and_deploys(setup_database):
    version_dir = setup_database
    job_id = seed_retrain_job()
    seed_labeled_url(url="https://phish1.example")
    seed_labeled_url(url="https://phish2.example", true_label="clean", label="phishing")

    with patch.object(
        ModelTrainer, "_fetch_html", return_value="<html>fake</html>"
    ), patch.object(
        ModelTrainer,
        "_train_url_model",
        return_value={"val_f1": 0.91},
    ), patch.object(
        ModelTrainer,
        "_train_html_model",
        return_value={"val_f1": 0.87},
    ), patch.object(
        trainer_module.model_registry, "deploy"
    ) as mock_deploy:
        asyncio.run(ModelTrainer().run_retraining(job_id))

    job = get_job(job_id)
    assert job.status == "complete"
    assert job.started_at is not None
    assert job.completed_at is not None

    mock_deploy.assert_called_once_with(1)

    metadata_path = version_dir / "v1" / "metadata.json"
    assert metadata_path.exists()
    with open(metadata_path) as f:
        metadata = json.load(f)

    assert metadata["version"] == 1
    assert metadata["val_f1_url"] == 0.91
    assert metadata["val_f1_html"] == 0.87
    assert metadata["dataset_size"] == 2
    assert metadata["augmented_samples"] >= 0
    assert "attack_type_counts" in metadata


def test_run_retraining_marks_failed_on_exception(setup_database):
    job_id = seed_retrain_job()
    seed_labeled_url()

    with patch.object(
        ModelTrainer, "_fetch_html", return_value="<html>fake</html>"
    ), patch.object(
        ModelTrainer, "_train_url_model", side_effect=RuntimeError("GPU on fire")
    ):
        asyncio.run(ModelTrainer().run_retraining(job_id))

    job = get_job(job_id)
    assert job.status == "failed"


def test_run_retraining_missing_job_id_does_not_crash(setup_database):
    # should log and return, not raise
    asyncio.run(ModelTrainer().run_retraining(99999))


def test_next_version_increments_from_existing_directories(setup_database):
    version_dir = setup_database
    (version_dir / "v1").mkdir()
    (version_dir / "v2").mkdir()
    (version_dir / "not-a-version").mkdir()

    trainer = ModelTrainer()
    assert trainer._next_version() == 3


def test_next_version_starts_at_1_when_empty(setup_database):
    trainer = ModelTrainer()
    assert trainer._next_version() == 1


def test_build_training_dataframe_includes_labeled_and_high_confidence_rows(
    setup_database,
):
    seed_labeled_url(url="https://labeled.example", true_label="phishing")
    seed_labeled_url(
        url="https://high-conf.example",
        true_label=None,
        confidence=0.9,
        label="phishing",
    )
    seed_labeled_url(
        url="https://low-conf.example",
        true_label=None,
        confidence=0.5,
        label="phishing",
    )

    with patch.object(ModelTrainer, "_fetch_html", return_value=""):
        df = ModelTrainer()._build_training_dataframe()

    assert set(df["url"]) == {"https://labeled.example", "https://high-conf.example"}
    assert list(df.columns) == ["url", "html_features", "label"]
