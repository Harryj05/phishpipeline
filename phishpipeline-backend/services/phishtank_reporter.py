"""PhishTank reporting channel.

PhishTank requires an account and API key from phishtank.org.
Without a key, we submit via the public web form as a fallback.
PhishTank API endpoint: https://www.phishtank.com/add_web_phish.php
"""

import logging
import os
from urllib.parse import quote_plus

import httpx

logger = logging.getLogger(__name__)

PHISHTANK_API_URL = "https://www.phishtank.com/add_web_phish.php"
PHISHTANK_REPORT_FORM = "https://www.phishtank.com/add_phish.php"
REQUEST_TIMEOUT_SECONDS = 15.0


async def report_phishtank(url: str) -> dict:
    result = {"channel": "phishtank", "status": "pending",
              "response_code": None, "response_body": None,
              "error_message": None}

    api_key = os.environ.get("PHISHTANK_API_KEY")

    if api_key:
        # API submission path
        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
                r = await client.post(
                    PHISHTANK_API_URL,
                    data={"phish_url": url, "format": "json", "app_key": api_key},
                )
                result["response_code"] = r.status_code
                if r.status_code == 200:
                    try:
                        body = r.json()
                        result["status"] = "submitted"
                        result["response_body"] = str(body)
                    except Exception:
                        result["status"] = "submitted"
                        result["response_body"] = r.text[:500]
                else:
                    result["status"] = "failed"
                    result["error_message"] = f"HTTP {r.status_code}: {r.text[:200]}"
        except Exception as e:
            result["status"] = "failed"
            result["error_message"] = str(e)
    else:
        # No key — record as skipped with form URL for manual follow-up
        logger.warning(
            "PHISHTANK_API_KEY not set — skipping API submission for %s", url
        )
        result["status"] = "skipped"
        result["response_body"] = (
            f"No API key. Manual submission: "
            f"{PHISHTANK_REPORT_FORM}?phish_url={quote_plus(url)}"
        )

    return result
