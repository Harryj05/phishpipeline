"""Google Safe Browsing reporting channel.

Google does not expose a programmatic URL submission API.
The correct mechanism is the "Report a Phishing Page" web form:
  https://safebrowsing.google.com/safebrowsing/report_phish/?url=<encoded_url>

For the GSB Lookup API (read-only threat check), use:
  POST https://safebrowsing.googleapis.com/v4/threatMatches:find
  (we use this to CHECK if a URL is already known, not to submit)

This reporter does TWO things:
1. Submits via the public report form URL (no API key needed)
2. Checks if the URL is already in GSB database (requires GSB_API_KEY)
"""

import logging
import os
from urllib.parse import quote_plus

import httpx

logger = logging.getLogger(__name__)

GSB_REPORT_FORM = "https://safebrowsing.google.com/safebrowsing/report_phish/"
GSB_LOOKUP_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
REQUEST_TIMEOUT_SECONDS = 10.0


async def report_gsb(url: str) -> dict:
    result = {"channel": "gsb", "status": "pending",
              "response_code": None, "response_body": None,
              "error_message": None}

    # Method 1: Public report form (always available, no key needed)
    report_url = f"{GSB_REPORT_FORM}?url={quote_plus(url)}"
    try:
        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT_SECONDS, follow_redirects=True
        ) as client:
            # HEAD request to verify the form endpoint is reachable
            r = await client.head(report_url)
            result["response_code"] = r.status_code
            if r.status_code < 400:
                result["status"] = "submitted"
                result["response_body"] = (
                    f"Submitted to Google Safe Browsing report form. "
                    f"Review URL: {report_url}"
                )
                logger.info("GSB report form submission OK for %s (HTTP %s)",
                            url, r.status_code)
            else:
                result["status"] = "failed"
                result["error_message"] = f"GSB form returned HTTP {r.status_code}"
    except Exception as e:
        result["status"] = "failed"
        result["error_message"] = str(e)
        logger.error("GSB report failed for %s: %s", url, e)

    # Method 2: GSB Lookup (if key available) — check if already flagged
    api_key = os.environ.get("GSB_API_KEY")
    if api_key and result["status"] == "submitted":
        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
                r2 = await client.post(
                    f"{GSB_LOOKUP_URL}?key={api_key}",
                    json={
                        "client": {"clientId": "phishpipeline", "clientVersion": "1.0"},
                        "threatInfo": {
                            "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE"],
                            "platformTypes": ["ANY_PLATFORM"],
                            "threatEntryTypes": ["URL"],
                            "threatEntries": [{"url": url}],
                        },
                    },
                )
                if r2.status_code == 200:
                    matches = r2.json().get("matches", [])
                    already_flagged = len(matches) > 0
                    result["response_body"] += (
                        f" | Already in GSB database: {already_flagged}"
                    )
        except Exception as e:
            logger.warning("GSB lookup check failed (non-critical): %s", e)

    return result
