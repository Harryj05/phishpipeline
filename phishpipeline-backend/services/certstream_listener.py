import asyncio
import base64
import logging
import os
import re
import struct

import httpx
from cryptography import x509

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# The free calidog CertStream websocket (wss://certstream.calidog.io/) no
# longer streams data — the handshake succeeds but no events are ever sent.
# Instead we poll a live Certificate Transparency log directly over its
# REST API (RFC 6962). Log shards rotate roughly every half-year; check
# https://www.gstatic.com/ct/log_list/v3/log_list.json for the current
# "usable" Argon/Xenon/Nimbus shard if this one goes read-only.
CT_LOG_BASE_URL = "https://ct.googleapis.com/logs/us1/argon2026h2/"
INGEST_ENDPOINT = os.environ.get(
    "PHISHPIPELINE_INGEST_URL", "http://localhost:8000/api/ingest-domain"
)
POLL_INTERVAL_SECONDS = 10
ENTRIES_PER_POLL = 64
RECONNECT_DELAY_SECONDS = 5

ALLOWLIST = {
    "google.com",
    "googleapis.com",
    "cloudflare.com",
    "amazonaws.com",
    "microsoft.com",
    "apple.com",
    "facebook.com",
    "twitter.com",
    "linkedin.com",
    "github.com",
    "cloudfront.net",
    "fastly.net",
    "akamai.net",
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "secure",
    "verify",
    "update",
    "account",
    "banking",
    "signin",
    "wallet",
    "confirm",
    "password",
    "support",
}

BRAND_KEYWORDS = {
    "paypal",
    "apple",
    "google",
    "amazon",
    "microsoft",
    "netflix",
    "instagram",
    "facebook",
    "bank",
    "crypto",
}

SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".club",
    ".online",
    ".site",
    ".live",
    ".info",
    ".cn",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
}

MIN_SUSPICION_SCORE = 20


def should_filter(domain: str) -> bool:
    if domain.startswith("*."):
        return True
    if domain in ALLOWLIST:
        return True
    if len(domain) < 5 or len(domain) > 60:
        return True
    if "." not in domain:
        return True
    return False


def score_domain(domain: str) -> int:
    """Heuristic suspicion score, calibrated so that > 35 means
    phishing-level suspicion and <= 35 means benign-leaning.

    Content signals (phishing keywords, impersonated brands, and
    especially the combination of the two — "paypal-login",
    "apple-verify") carry most of the weight. Structural signals
    (length, digits, deep subdomains) are weak on their own because
    legitimate cloud/CDN infrastructure domains routinely exhibit all
    of them, so alone they stay at or below the 35 boundary.
    """
    score = 0
    lowered = domain.lower()

    has_keyword = any(keyword in lowered for keyword in SUSPICIOUS_KEYWORDS)
    has_brand = any(keyword in lowered for keyword in BRAND_KEYWORDS)

    if has_keyword:
        score += 25

    if has_brand:
        score += 20

    # Brand + action keyword together is the classic phishing pattern.
    if has_keyword and has_brand:
        score += 15

    if any(lowered.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 15

    # Bare IP address as the host — no legitimate site serves users this way.
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", lowered):
        score += 25

    if lowered.count("-") > 3:
        score += 10

    # Digit-dominated leading label (e.g. "83625-secure") reads as generated.
    leading_label = lowered.split(".")[0]
    if leading_label and (
        sum(char.isdigit() for char in leading_label) / len(leading_label) > 0.5
    ):
        score += 10

    if sum(char.isdigit() for char in lowered) > 4:
        score += 5

    if len(domain) > 40:
        score += 5

    if lowered.count(".") > 4:
        score += 5

    return min(score, 100)


def extract_domains_from_entry(entry: dict) -> list:
    """Decode a get-entries leaf into its certificate's SAN DNS names.

    Each entry is a MerkleTreeLeaf (RFC 6962 section 3.4). entry_type 0 is
    a plain X.509 cert embedded directly in leaf_input; entry_type 1 is a
    precert, whose actual (poisoned) certificate lives in extra_data.
    """
    try:
        leaf_input = base64.b64decode(entry["leaf_input"])
        entry_type = struct.unpack(">H", leaf_input[10:12])[0]

        if entry_type == 0:
            length = int.from_bytes(leaf_input[12:15], "big")
            cert_der = leaf_input[15 : 15 + length]
        elif entry_type == 1:
            extra_data = base64.b64decode(entry["extra_data"])
            length = int.from_bytes(extra_data[0:3], "big")
            cert_der = extra_data[3 : 3 + length]
        else:
            return []

        cert = x509.load_der_x509_certificate(cert_der)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return san.value.get_values_for_type(x509.DNSName)
    except Exception as exc:
        logger.error("Failed to parse CT log entry: %s", exc)
        return []


async def queue_domain(client: httpx.AsyncClient, domain: str, score: int) -> None:
    try:
        await client.post(
            INGEST_ENDPOINT,
            json={"url": domain, "source": "certstream", "suspicion_score": score},
        )
        print(f"QUEUED: {domain} (score: {score})")
    except Exception as exc:
        logger.error("Failed to queue domain %s: %s", domain, exc)


async def poll_ct_log(client: httpx.AsyncClient) -> None:
    sth_resp = await client.get(CT_LOG_BASE_URL + "ct/v1/get-sth")
    sth_resp.raise_for_status()
    position = sth_resp.json()["tree_size"]
    logger.info("Starting CT log tail at tree_size=%s", position)

    while True:
        try:
            sth_resp = await client.get(CT_LOG_BASE_URL + "ct/v1/get-sth")
            sth_resp.raise_for_status()
            tree_size = sth_resp.json()["tree_size"]

            if tree_size > position:
                end = min(tree_size, position + ENTRIES_PER_POLL) - 1
                entries_resp = await client.get(
                    CT_LOG_BASE_URL + "ct/v1/get-entries",
                    params={"start": position, "end": end},
                )
                entries_resp.raise_for_status()
                entries = entries_resp.json().get("entries", [])

                for entry in entries:
                    for domain in extract_domains_from_entry(entry):
                        if not domain or should_filter(domain):
                            continue
                        score = score_domain(domain)
                        if score < MIN_SUSPICION_SCORE:
                            continue
                        await queue_domain(client, domain, score)

                position += len(entries) if entries else 1
        except Exception as exc:
            logger.error("CT log poll error: %s", exc)

        await asyncio.sleep(POLL_INTERVAL_SECONDS)


async def run_listener() -> None:
    async with httpx.AsyncClient(timeout=20.0) as client:
        while True:
            try:
                await poll_ct_log(client)
            except Exception as exc:
                logger.error("Listener crashed: %s", exc)

            logger.info(
                "Reconnecting in %s seconds...", RECONNECT_DELAY_SECONDS
            )
            await asyncio.sleep(RECONNECT_DELAY_SECONDS)


if __name__ == "__main__":
    asyncio.run(run_listener())
