"""OpenPhish reporting channel.

OpenPhish is a read-only feed — there is no public URL submission API.
This reporter records a "manual" action URL for follow-up.
"""

import logging

logger = logging.getLogger(__name__)

OPENPHISH_CONTACT = "https://openphish.com/contact.html"


async def report_openphish(url: str) -> dict:
    logger.info(
        "OpenPhish: no public submission API — logging for manual follow-up: %s",
        url,
    )
    return {
        "channel": "openphish",
        "status": "skipped",
        "response_code": None,
        "response_body": (
            f"OpenPhish has no public submission API. "
            f"Contact: {OPENPHISH_CONTACT}"
        ),
        "error_message": None,
    }
