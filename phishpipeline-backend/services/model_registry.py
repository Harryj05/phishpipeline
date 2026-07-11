"""Singleton holding whichever URL/HTML models are currently deployed.

Split out from services/trainer.py so that url_transformer.py and
html_classifier.py can import the registry without creating a circular
import (trainer.py itself imports those two modules for their MODEL_NAME
constants).
"""

import json
import logging
from pathlib import Path
from typing import Optional

from transformers import AutoModelForSequenceClassification, AutoTokenizer

logger = logging.getLogger(__name__)

VERSION_DIR = "models/versions"


class ModelRegistry:
    _instance: Optional["ModelRegistry"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.current_version = None
        self.url_model = None
        self.url_tokenizer = None
        self.html_model = None
        self.html_tokenizer = None

    def deploy(self, version: int) -> None:
        version_dir = Path(VERSION_DIR) / f"v{version}"
        url_dir = version_dir / "url_model"
        html_dir = version_dir / "html_model"

        new_url_tokenizer = AutoTokenizer.from_pretrained(str(url_dir))
        new_url_model = AutoModelForSequenceClassification.from_pretrained(
            str(url_dir)
        )
        new_url_model.eval()

        new_html_tokenizer = AutoTokenizer.from_pretrained(str(html_dir))
        new_html_model = AutoModelForSequenceClassification.from_pretrained(
            str(html_dir)
        )
        new_html_model.eval()

        # Atomic swap: only reassign once every load has succeeded, so a
        # bad version directory never leaves the registry half-updated.
        self.url_tokenizer = new_url_tokenizer
        self.url_model = new_url_model
        self.html_tokenizer = new_html_tokenizer
        self.html_model = new_html_model
        self.current_version = version

        logger.info("Deployed model version %s", version)

    def get_current_version_info(self) -> dict:
        if self.current_version is None:
            return {"version": None}

        metadata_path = Path(VERSION_DIR) / f"v{self.current_version}" / "metadata.json"
        if not metadata_path.exists():
            return {"version": self.current_version}

        with open(metadata_path) as f:
            return json.load(f)

    def list_versions(self) -> list:
        base = Path(VERSION_DIR)
        if not base.exists():
            return []

        versions = []
        for entry in sorted(base.iterdir()):
            if not entry.is_dir() or not entry.name.startswith("v"):
                continue
            metadata_path = entry / "metadata.json"
            if not metadata_path.exists():
                continue
            with open(metadata_path) as f:
                versions.append(json.load(f))
        return versions


model_registry = ModelRegistry()
