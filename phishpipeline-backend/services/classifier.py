"""Two-stage classification orchestrator.

Stage 1 (URL_ONLY) always runs. If its confidence is below
STAGE2_CONFIDENCE_THRESHOLD, Stage 2 (HYBRID) fetches and analyzes the
page's HTML for a second opinion. Any Stage 2 failure (fetch error,
timeout, parse error) falls back to the Stage 1 result.
"""

import asyncio
import logging

from services import html_classifier, html_parser, url_transformer

logger = logging.getLogger(__name__)

STAGE2_CONFIDENCE_THRESHOLD = 0.7

# Attack category mapping, keyed by the adversarial flag that identifies it
# (see services/html_parser.py for where each flag is raised).
_ATTACK_CATEGORY_BY_FLAG = {
    "js_redirect_early": "js_evasion",
    "hidden_iframe": "clickjacking",
    "hidden_text_css": "dom_cloaking",
    "base64_script_block": "text_encoding",
}


def determine_attack_category(adversarial_flags: list) -> str:
    for flag, category in _ATTACK_CATEGORY_BY_FLAG.items():
        if flag in adversarial_flags:
            return category
    return "regular"


async def classify(url: str) -> dict:
    stage1_result = await asyncio.to_thread(url_transformer.classify_url, url)

    if stage1_result["confidence"] >= STAGE2_CONFIDENCE_THRESHOLD:
        # URL-only verdict: no HTML was inspected, so no adversarial
        # technique was observed — which is what "regular" means.
        stage1_result["attack_category"] = "regular"
        return stage1_result

    try:
        parsed = await html_parser.analyze_url(url)
        result = await asyncio.to_thread(html_classifier.classify_html, parsed)
        result["attack_category"] = determine_attack_category(
            parsed.get("adversarial_flags", [])
        )
        return result
    except Exception as exc:
        logger.error("Stage 2 HTML classification failed for %s: %s", url, exc)
        fallback = dict(stage1_result)
        fallback["stage"] = "URL_ONLY_FALLBACK"
        fallback["attack_category"] = "regular"
        return fallback
