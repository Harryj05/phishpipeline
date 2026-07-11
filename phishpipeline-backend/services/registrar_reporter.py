"""Registrar/hosting abuse reporting channel: WHOIS lookup + abuse email."""

import asyncio
import logging
import os
import smtplib
from email.mime.text import MIMEText
from urllib.parse import urlparse

import whois

logger = logging.getLogger(__name__)

SMTP_TIMEOUT_SECONDS = 10


def _extract_domain(url: str) -> str:
    return urlparse(url).netloc


def _whois_lookup(domain: str) -> dict:
    record = whois.whois(domain)

    def _get(field):
        if isinstance(record, dict):
            return record.get(field)
        return getattr(record, field, None)

    registrar = _get("registrar")
    emails = _get("emails")
    if isinstance(emails, list):
        abuse_email = emails[0] if emails else None
    else:
        abuse_email = emails

    name_servers = _get("name_servers")

    return {
        "registrar": registrar,
        "abuse_email": abuse_email,
        "name_servers": name_servers,
    }


def _build_abuse_email_body(url: str, timestamp, confidence: float) -> str:
    return (
        "This is an automated abuse report from PhishPipeline.\n\n"
        "A phishing site has been detected at the following URL:\n\n"
        f"  URL: {url}\n"
        f"  Detected at: {timestamp}\n"
        f"  Confidence score: {confidence:.2f}\n\n"
        "We request that you investigate this domain and take down or "
        "suspend it if it violates your terms of service.\n\n"
        "— PhishPipeline Automated Abuse Reporting"
    )


def _send_abuse_email(domain: str, abuse_email: str, url: str, timestamp, confidence: float) -> None:
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    from_email = os.environ.get("ABUSE_FROM_EMAIL")

    if not all([smtp_host, smtp_user, smtp_pass, from_email]):
        raise RuntimeError("SMTP credentials are not fully configured")

    message = MIMEText(_build_abuse_email_body(url, timestamp, confidence))
    message["Subject"] = f"Phishing Site Report: {domain}"
    message["From"] = from_email
    message["To"] = abuse_email

    with smtplib.SMTP(smtp_host, smtp_port, timeout=SMTP_TIMEOUT_SECONDS) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(from_email, [abuse_email], message.as_string())


async def report_registrar(url: str, timestamp=None, confidence: float = 0.0) -> dict:
    domain = _extract_domain(url)

    try:
        whois_info = await asyncio.to_thread(_whois_lookup, domain)
    except Exception as exc:
        logger.error("WHOIS lookup failed for %s: %s", domain, exc)
        return {
            "channel": "registrar",
            "status": "failed",
            "registrar": None,
            "abuse_email": None,
            "error_message": str(exc),
        }

    registrar = whois_info.get("registrar")
    abuse_email = whois_info.get("abuse_email")

    if not abuse_email:
        logger.warning(
            "No abuse email found via WHOIS for %s — skipping abuse email", domain
        )
        return {
            "channel": "registrar",
            "status": "skipped",
            "registrar": registrar,
            "abuse_email": None,
        }

    try:
        await asyncio.to_thread(
            _send_abuse_email, domain, abuse_email, url, timestamp, confidence or 0.0
        )
        return {
            "channel": "registrar",
            "status": "submitted",
            "registrar": registrar,
            "abuse_email": abuse_email,
        }
    except Exception as exc:
        logger.error("Abuse email failed for %s: %s", domain, exc)
        return {
            "channel": "registrar",
            "status": "failed",
            "registrar": registrar,
            "abuse_email": abuse_email,
            "error_message": str(exc),
        }
