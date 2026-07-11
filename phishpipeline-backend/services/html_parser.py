"""Stage 2 input prep: fetch a page's HTML and extract structural features
plus a set of adversarial-patch heuristics."""

import logging
import re
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

FETCH_TIMEOUT_SECONDS = 5.0

JS_REDIRECT_PATTERN = re.compile(r"(window|document)\.location", re.IGNORECASE)
BASE64_BLOCK_PATTERN = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
HIDDEN_TEXT_PATTERN = re.compile(r"text-indent\s*:\s*-9999px", re.IGNORECASE)
DOMAIN_MISMATCH_THRESHOLD = 0.3


async def fetch_html(url: str) -> str:
    async with httpx.AsyncClient(
        follow_redirects=True, timeout=FETCH_TIMEOUT_SECONDS
    ) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.text


def _domain_mismatch_ratio(links: list, page_domain: str) -> float:
    if not links:
        return 0.0

    mismatched = 0
    checked = 0
    for href in links:
        try:
            link_domain = urlparse(href).netloc
        except ValueError:
            continue
        if not link_domain:
            continue
        checked += 1
        if link_domain != page_domain:
            mismatched += 1

    if checked == 0:
        return 0.0
    return mismatched / checked


def _has_hidden_iframe(soup: BeautifulSoup) -> bool:
    for iframe in soup.find_all("iframe"):
        style = (iframe.get("style") or "").replace(" ", "").lower()
        width = str(iframe.get("width", "")).strip()
        if "opacity:0" in style or width == "0":
            return True
    return False


def _has_base64_script_block(soup: BeautifulSoup) -> bool:
    for script in soup.find_all("script"):
        if script.get("src"):
            continue
        text = script.string or ""
        if text and BASE64_BLOCK_PATTERN.search(text):
            return True
    return False


def parse_html(url: str, html: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    page_domain = urlparse(url).netloc

    title = soup.title.get_text(strip=True) if soup.title else ""
    links = [a["href"] for a in soup.find_all("a", href=True)]
    form_actions = [f["action"] for f in soup.find_all("form", action=True)]
    input_names = [i["name"] for i in soup.find_all("input", attrs={"name": True})]
    script_srcs = [s["src"] for s in soup.find_all("script", src=True)]
    meta_refresh_tags = soup.find_all(
        "meta", attrs={"http-equiv": re.compile("refresh", re.I)}
    )
    favicon_tag = soup.find("link", rel=re.compile("icon", re.I))

    features = {
        "title": title,
        "links": links,
        "form_actions": form_actions,
        "input_names": input_names,
        "script_srcs": script_srcs,
        "meta_refresh": len(meta_refresh_tags) > 0,
        "favicon": (favicon_tag.get("href") or "") if favicon_tag else "",
    }

    adversarial_flags = []

    if JS_REDIRECT_PATTERN.search(html[:500]):
        adversarial_flags.append("js_redirect_early")

    if _has_hidden_iframe(soup):
        adversarial_flags.append("hidden_iframe")

    if _domain_mismatch_ratio(links, page_domain) > DOMAIN_MISMATCH_THRESHOLD:
        adversarial_flags.append("domain_mismatch_links")

    if _has_base64_script_block(soup):
        adversarial_flags.append("base64_script_block")

    if HIDDEN_TEXT_PATTERN.search(html):
        adversarial_flags.append("hidden_text_css")

    return {"features": features, "adversarial_flags": adversarial_flags}


async def analyze_url(url: str) -> dict:
    html = await fetch_html(url)
    return parse_html(url, html)
