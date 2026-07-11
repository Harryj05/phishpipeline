import pytest

from services import html_classifier, url_transformer
from services.takedown_tracker import TakedownTracker


@pytest.fixture(autouse=True)
def stub_model_preload(monkeypatch):
    """Prevent real model downloads/loads from running during tests."""
    monkeypatch.setattr(url_transformer, "preload", lambda: None)
    monkeypatch.setattr(html_classifier, "preload", lambda: None)


@pytest.fixture(autouse=True)
def stub_takedown_tracker_start(monkeypatch):
    """Prevent the real infinite polling loop from starting during tests."""

    async def fake_start(self):
        return None

    monkeypatch.setattr(TakedownTracker, "start", fake_start)
