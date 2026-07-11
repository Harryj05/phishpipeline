"""Stage 1 classifier: fine-tuned BERT model over the raw URL string."""

import logging

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from services.model_registry import model_registry

logger = logging.getLogger(__name__)

MODEL_NAME = "ealvaradob/bert-finetuned-phishing"
MAX_LENGTH = 128

# CPU-only for now. Phase 3: set DEVICE = "cuda" (with a torch.cuda.is_available()
# guard) here to move inference onto GPU once one is available.
DEVICE = "cpu"

_tokenizer = None
_model = None

PHISHING_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "signin", "wallet", "password", "paypal", "apple",
    "amazon", "microsoft", "netflix",
]
SUSPICIOUS_TLDS = [".xyz", ".top", ".live", ".click", ".gq", ".ml", ".cf"]


def _heuristic_classify(url: str) -> dict:
    url_lower = url.lower()
    score = 0
    for kw in PHISHING_KEYWORDS:
        if kw in url_lower:
            score += 15
    for tld in SUSPICIOUS_TLDS:
        if url_lower.endswith(tld) or f"{tld}/" in url_lower:
            score += 20
    hyphen_count = url_lower.count("-")
    if hyphen_count > 3:
        score += 10
    parts = url_lower.split(".")
    if len(parts) > 5:
        score += 10
    confidence = min(score / 100, 0.95) if score > 0 else 0.08
    label = "phishing" if confidence >= 0.5 else "clean"
    return {
        "label": label,
        "confidence": confidence,
        "stage": "URL_ONLY",
        "adversarial_flags": [],
        "_stub": True,
    }


def _load():
    global _tokenizer, _model

    # A retrained/rolled-back version deployed via ModelRegistry always
    # takes priority over the base HuggingFace hub checkpoint below.
    if model_registry.url_model is not None:
        return model_registry.url_tokenizer, model_registry.url_model

    if _model is None:
        try:
            logger.info("Loading Stage 1 URL transformer model: %s", MODEL_NAME)
            _tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
            _model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
            _model.to(DEVICE)
            _model.eval()
        except Exception as e:
            logger.warning(
                "Could not load BERT model (%s). Falling back to heuristic stub.", e
            )
            _tokenizer = None
            _model = "stub"
    return _tokenizer, _model


def preload() -> None:
    """Force the model/tokenizer to load now instead of on first request."""
    _load()


def is_loaded() -> bool:
    return model_registry.url_model is not None or _model is not None


def _resolve_label(label_id: int, model) -> str:
    id2label = getattr(model.config, "id2label", {}) or {}
    raw_label = id2label.get(label_id, id2label.get(str(label_id), str(label_id)))
    raw_label = str(raw_label).lower()

    if "phish" in raw_label:
        return "phishing"
    if "benign" in raw_label or "safe" in raw_label or "legit" in raw_label:
        return "clean"

    # Fallback convention if the label text isn't self-describing: index 1 == phishing.
    return "phishing" if label_id == 1 else "clean"


def classify_url(url: str) -> dict:
    tokenizer, model = _load()

    # Heuristic stub fallback (no model available)
    if model == "stub" or model is None:
        return _heuristic_classify(url)

    inputs = tokenizer(
        url,
        return_tensors="pt",
        truncation=True,
        padding=True,
        max_length=MAX_LENGTH,
    ).to(DEVICE)

    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=-1)[0]

    label_id = int(torch.argmax(probs).item())
    confidence = float(probs[label_id].item())
    label = _resolve_label(label_id, model)

    return {"label": label, "confidence": confidence, "stage": "URL_ONLY"}
