"""
End-to-end integration test.
Run with: PHISHPIPELINE_SKIP_MODEL_PRELOAD=1 pytest tests/test_e2e.py -v
"""
import os
os.environ["PHISHPIPELINE_SKIP_MODEL_PRELOAD"] = "1"
os.environ["PHISHPIPELINE_SKIP_CERTSTREAM"] = "1"
os.environ["PHISHPIPELINE_SKIP_TAKEDOWN_TRACKER"] = "1"

import pytest
from fastapi.testclient import TestClient
from main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_root(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert "status" in r.json()


def test_stats(client):
    r = client.get("/api/stats")
    assert r.status_code == 200
    data = r.json()
    assert "domainsScanned" in data
    assert "phishingCount" in data


def test_queue_empty(client):
    r = client.get("/api/queue")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_submit_url_clean(client):
    r = client.post("/api/submit-url", json={"url": "https://google.com"})
    assert r.status_code == 200
    data = r.json()
    assert data["label"] in ("phishing", "clean")
    assert 0 <= data["confidence"] <= 1
    assert data["stage"] in ("URL_ONLY", "HYBRID", "URL_ONLY_FALLBACK")


def test_submit_url_phishing(client):
    r = client.post(
        "/api/submit-url",
        json={"url": "https://secure-paypal-verify-account.xyz/login"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["label"] in ("phishing", "clean")


def test_submit_invalid_url(client):
    r = client.post("/api/submit-url", json={"url": "not-a-url"})
    assert r.status_code == 422


def test_ingest_domain(client):
    r = client.post(
        "/api/ingest-domain",
        json={
            "url": "apple-id-verify.xyz",
            "source": "certstream",
            "suspicion_score": 85,
        },
    )
    assert r.status_code == 200


def test_queue_has_entries(client):
    r = client.get("/api/queue")
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) >= 2  # from above submits


def test_admin_flagged(client):
    r = client.get("/api/admin/flagged")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_admin_stats(client):
    r = client.get("/api/admin/stats")
    assert r.status_code == 200
    data = r.json()
    assert "total_reviewed" in data
    assert "fp_count" in data


def test_admin_label(client):
    # Get a flagged URL id first
    queue = client.get("/api/queue").json()
    if not queue:
        pytest.skip("No entries in queue")
    entry_id = queue[0]["id"]
    r = client.post(
        "/api/admin/label",
        json={"id": entry_id, "true_label": "phishing", "labeled_by": "test"},
    )
    assert r.status_code == 200


def test_analytics(client):
    r = client.get("/api/analytics/takedown")
    assert r.status_code == 200
    data = r.json()
    assert "overall" in data
    assert "by_category" in data
    assert "timeline" in data


def test_analytics_live(client):
    r = client.get("/api/analytics/takedown/live")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_reports(client):
    r = client.get("/api/reports")
    assert r.status_code == 200


def test_model_info(client):
    r = client.get("/api/model-info")
    assert r.status_code == 200
    data = r.json()
    assert "stage1_model" in data
