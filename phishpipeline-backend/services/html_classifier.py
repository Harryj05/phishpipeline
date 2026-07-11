"""Stage 2 classifier over parsed HTML features.

Two paths:

1. Model path — used ONLY when a fine-tuned checkpoint has been deployed
   via ModelRegistry (UC7 retraining). Base 'google/mobilebert-uncased'
   has no sequence-classification head, so a fresh `num_labels=2` head is
   randomly initialised and its predictions are close to random noise —
   it must never decide verdicts.
2. Rule-based path — the default until a fine-tuned model exists: a
   weighted heuristic over the structural HTML signals extracted by
   services/html_parser.py (adversarial flags, forms, links, favicon
   origin, external scripts, title keywords, meta refresh).
"""

import logging

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from services.model_registry import model_registry

logger = logging.getLogger(__name__)

MODEL_NAME = "google/mobilebert-uncased"
MAX_LENGTH = 256

# CPU-only for now. Phase 3: set DEVICE = "cuda" (with a torch.cuda.is_available()
# guard) here to move inference onto GPU once one is available.
DEVICE = "cpu"

_tokenizer = None
_model = None


def _load():
    global _tokenizer, _model

    # A retrained/rolled-back version deployed via ModelRegistry always
    # takes priority over the base HuggingFace hub checkpoint below.
    if model_registry.html_model is not None:
        return model_registry.html_tokenizer, model_registry.html_model

    if _model is None:
        try:
            logger.info("Loading Stage 2 HTML classifier model: %s", MODEL_NAME)
            _tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
            _model = AutoModelForSequenceClassification.from_pretrained(
                MODEL_NAME, num_labels=2
            )
            _model.to(DEVICE)
            _model.eval()
        except Exception as e:
            logger.warning(
                "Could not load MobileBERT model (%s). Falling back to stub.", e
            )
            _tokenizer = None
            _model = "stub"
    return _tokenizer, _model


def preload() -> None:
    """Force the model/tokenizer to load now instead of on first request."""
    _load()


def is_loaded() -> bool:
    return model_registry.html_model is not None or _model is not None


def _serialize_features(parsed: dict) -> str:
    features = parsed.get("features", {})
    flags = parsed.get("adversarial_flags", [])

    title = features.get("title") or ""
    link_count = len(features.get("links") or [])
    form_count = len(features.get("form_actions") or [])

    return (
        f"title: {title} | links: {link_count} | "
        f"forms: {form_count} | flags: {', '.join(flags)}"
    )


ADVERSARIAL_FLAG_WEIGHTS = {
    "js_redirect_early": 30,
    "hidden_iframe": 25,
    "base64_script_block": 20,
    "hidden_text_css": 15,
    "domain_mismatch_links": 20,
}

TITLE_KEYWORDS = [
    "verify",
    "secure",
    "login",
    "account",
    "update",
    "confirm",
    "alert",
    "suspended",
    "unusual",
    "sign in",
]


def _rule_based_classify(parsed: dict) -> dict:
    adversarial_flags = parsed.get("adversarial_flags", [])
    features = parsed.get("features", {})

    score = 0

    # Adversarial signals (strongest indicators)
    for flag in adversarial_flags:
        score += ADVERSARIAL_FLAG_WEIGHTS.get(flag, 10)

    # Form actions pointing to external domains
    form_actions = features.get("form_actions") or []
    if len(form_actions) > 0:
        score += 15

    # High link count relative to forms (credential harvesting pattern)
    links = features.get("links") or []
    if len(links) > 20 and len(form_actions) > 0:
        score += 10

    # Favicon from external domain (common phishing signal)
    favicon = features.get("favicon") or ""
    if favicon and not favicon.startswith("/") and "http" in favicon:
        score += 10

    # Script sources from external domains
    scripts = features.get("script_srcs") or []
    external_scripts = [s for s in scripts if s.startswith("http")]
    if len(external_scripts) > 3:
        score += 10

    # Title contains phishing keywords
    title = (features.get("title") or "").lower()
    for kw in TITLE_KEYWORDS:
        if kw in title:
            score += 8
            break  # only count once

    # No title at all (common for quick phishing pages)
    if not title:
        score += 5

    # Meta refresh (drive-by redirect)
    if features.get("meta_refresh"):
        score += 20

    confidence = min(score / 100.0, 0.97)
    label = "phishing" if confidence >= 0.35 else "clean"

    return {
        "label": label,
        "confidence": round(confidence, 3),
        "stage": "HYBRID",
        "adversarial_flags": adversarial_flags,
        "_rule_based": True,
    }


def classify_html(parsed: dict) -> dict:
    adversarial_flags = parsed.get("adversarial_flags", [])

    # Rule-based scoring unless a real fine-tuned model has been deployed
    # via ModelRegistry. The base MobileBERT checkpoint loads fine but its
    # classification head is randomly initialised, so it must not be used
    # to decide verdicts.
    if model_registry.html_model is None:
        return _rule_based_classify(parsed)

    # Model-based path (only used when a real fine-tuned model is deployed
    # via ModelRegistry after UC7 retraining).
    tokenizer, model = _load()
    text = _serialize_features(parsed)
    inputs = tokenizer(
        text,
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
    label = "phishing" if label_id == 1 else "clean"
    return {
        "label": label,
        "confidence": confidence,
        "stage": "HYBRID",
        "adversarial_flags": adversarial_flags,
    }
