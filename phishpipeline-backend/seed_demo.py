"""
Seed the database with realistic demo data for presentations.
Run: python seed_demo.py           # add data without clearing
     python seed_demo.py --reset   # clear then reseed (clean demo state)
Backend must be running on port 8000.
"""

import sys
import time

import httpx

# Windows consoles default to cp1252, which can't print ✓/✗/⚠.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = "http://localhost:8000"

PHISHING_DOMAINS = [
    ("secure-paypal-verify-account.xyz", 91),
    ("apple-id-signin-locked.online", 84),
    ("login-chase-bank-alert.info", 77),
    ("microsoft-account-security.live", 72),
    ("amazon-order-suspended.click", 68),
    ("netflix-billing-update.top", 65),
    ("paypal-customer-support-verify.gq", 88),
    ("wellsfargo-secure-login.xyz", 79),
]

CLEAN_URLS = [
    "https://github.com",
    "https://stackoverflow.com",
    "https://docs.python.org",
    "https://reactjs.org",
    "https://fastapi.tiangolo.com",
]

MANUAL_URLS = [
    ("https://paypal-verify-account-now.xyz/login", "phishing demo"),
    ("https://accounts.google.com/signin", "clean demo"),
    ("https://apple-id-locked-verify.online/reset", "phishing demo"),
]


def seed():
    print("Seeding PhishPipeline demo data...\n")

    if "--reset" in sys.argv:
        r = httpx.delete(f"{BASE}/api/demo/reset", timeout=5)
        if r.status_code == 200:
            print("✓ Cleared existing data\n")
        elif r.status_code == 403:
            print("⚠ Reset not enabled (set PHISHPIPELINE_ALLOW_RESET=1)\n")
        else:
            print(f"⚠ Reset returned HTTP {r.status_code}\n")

    # Check backend
    try:
        r = httpx.get(f"{BASE}/api/health", timeout=5)
        print(f"✓ Backend connected ({r.json()})\n")
    except Exception as e:
        print(f"✗ Backend not reachable at {BASE}: {e}")
        print("  Start the backend first: uvicorn main:app --port 8000")
        return

    # Seed CT log domains (UC2)
    print("Seeding CT log detections (UC2)...")
    for domain, score in PHISHING_DOMAINS:
        r = httpx.post(f"{BASE}/api/ingest-domain", json={
            "url": domain,
            "source": "certstream",
            "suspicion_score": score,
        }, timeout=30)
        label = r.json().get("label", "?")
        conf = r.json().get("confidence", 0)
        print(f"  {domain[:40]:<40} score={score} → {label} ({conf:.0%})")
        time.sleep(0.3)

    print()

    # Seed manual URL checks (UC1)
    print("Seeding manual URL checks (UC1)...")
    for url, note in MANUAL_URLS:
        r = httpx.post(f"{BASE}/api/submit-url", json={"url": url}, timeout=30)
        if r.status_code == 200:
            data = r.json()
            print(f"  [{note}] {url[:45]:<45} → {data.get('label')} ({data.get('confidence', 0):.0%})")
        else:
            print(f"  ✗ Failed: {url} — HTTP {r.status_code}")
        time.sleep(0.3)

    print()

    # Summary
    r = httpx.get(f"{BASE}/api/stats", timeout=5)
    stats = r.json()
    print(f"✓ Done! Queue stats: {stats}")
    print(f"\nOpen http://localhost:5173 — the live feed should have data.")
    print(f"Open http://localhost:8000/docs to explore all endpoints.")


if __name__ == "__main__":
    seed()
