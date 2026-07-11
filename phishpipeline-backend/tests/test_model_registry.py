import json
from unittest.mock import MagicMock, patch

import pytest

import services.model_registry as registry_module
from services.model_registry import ModelRegistry


@pytest.fixture(autouse=True)
def isolated_registry(tmp_path, monkeypatch):
    monkeypatch.setattr(registry_module, "VERSION_DIR", str(tmp_path))
    # Reset singleton state between tests.
    ModelRegistry._instance = None
    registry = ModelRegistry()
    yield registry, tmp_path
    ModelRegistry._instance = None


def _write_version(base_dir, version, metadata):
    version_dir = base_dir / f"v{version}"
    (version_dir / "url_model").mkdir(parents=True, exist_ok=True)
    (version_dir / "html_model").mkdir(parents=True, exist_ok=True)
    with open(version_dir / "metadata.json", "w") as f:
        json.dump(metadata, f)


def test_list_versions_reads_all_metadata_files(isolated_registry):
    registry, tmp_path = isolated_registry
    _write_version(tmp_path, 1, {"version": 1, "val_f1_url": 0.8, "val_f1_html": 0.7})
    _write_version(tmp_path, 2, {"version": 2, "val_f1_url": 0.9, "val_f1_html": 0.85})

    versions = registry.list_versions()

    assert len(versions) == 2
    assert {v["version"] for v in versions} == {1, 2}


def test_list_versions_ignores_directories_without_metadata(isolated_registry):
    registry, tmp_path = isolated_registry
    (tmp_path / "v1" / "url_model").mkdir(parents=True)
    # no metadata.json written

    versions = registry.list_versions()

    assert versions == []


def test_deploy_swaps_current_models_and_version(isolated_registry):
    registry, tmp_path = isolated_registry
    _write_version(tmp_path, 3, {"version": 3, "val_f1_url": 0.9, "val_f1_html": 0.88})

    fake_tokenizer = MagicMock(name="tokenizer")
    fake_model = MagicMock(name="model")

    with patch.object(
        registry_module.AutoTokenizer, "from_pretrained", return_value=fake_tokenizer
    ), patch.object(
        registry_module.AutoModelForSequenceClassification,
        "from_pretrained",
        return_value=fake_model,
    ):
        registry.deploy(3)

    assert registry.current_version == 3
    assert registry.url_model is fake_model
    assert registry.html_model is fake_model
    assert registry.url_tokenizer is fake_tokenizer
    fake_model.eval.assert_called()


def test_deploy_does_not_partially_update_on_failure(isolated_registry):
    registry, tmp_path = isolated_registry
    _write_version(tmp_path, 1, {"version": 1})

    fake_tokenizer = MagicMock(name="tokenizer")
    fake_model = MagicMock(name="model")

    with patch.object(
        registry_module.AutoTokenizer, "from_pretrained", return_value=fake_tokenizer
    ), patch.object(
        registry_module.AutoModelForSequenceClassification,
        "from_pretrained",
        return_value=fake_model,
    ):
        registry.deploy(1)

    assert registry.current_version == 1

    # deploying a nonexistent version 99 should raise before mutating state
    with pytest.raises(Exception):
        registry.deploy(99)

    assert registry.current_version == 1
    assert registry.url_model is fake_model


def test_get_current_version_info_reads_metadata(isolated_registry):
    registry, tmp_path = isolated_registry
    _write_version(tmp_path, 5, {"version": 5, "val_f1_url": 0.95})

    fake_tokenizer = MagicMock()
    fake_model = MagicMock()
    with patch.object(
        registry_module.AutoTokenizer, "from_pretrained", return_value=fake_tokenizer
    ), patch.object(
        registry_module.AutoModelForSequenceClassification,
        "from_pretrained",
        return_value=fake_model,
    ):
        registry.deploy(5)

    info = registry.get_current_version_info()
    assert info["version"] == 5
    assert info["val_f1_url"] == 0.95


def test_get_current_version_info_with_no_deployment():
    ModelRegistry._instance = None
    registry = ModelRegistry()
    assert registry.get_current_version_info() == {"version": None}
    ModelRegistry._instance = None


def test_registry_is_a_singleton():
    ModelRegistry._instance = None
    a = ModelRegistry()
    b = ModelRegistry()
    assert a is b
    ModelRegistry._instance = None
