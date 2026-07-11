"""Manual smoke test against a running phishpipeline-backend instance.

Usage: start the backend (uvicorn main:app) then run:
    python tests/smoke_test.py
"""

import json

import httpx

BASE_URL = "http://localhost:8000"

EXPECTED_SUBMIT_FIELDS = {
    "id",
    "url",
    "source",
    "label",
    "confidence",
    "stage",
    "timestamp",
}


def print_response(label, response):
    print(f"\n--- {label} ---")
    print(f"Status: {response.status_code}")
    try:
        print(json.dumps(response.json(), indent=2))
    except ValueError:
        print(response.text)


def check_submit_response(response):
    if response.status_code != 200:
        return False
    try:
        data = response.json()
    except ValueError:
        return False
    return EXPECTED_SUBMIT_FIELDS.issubset(data.keys())


def run_submit_test(client, url):
    response = client.post(f"{BASE_URL}/api/submit-url", json={"url": url})
    print_response(f"POST /api/submit-url ({url})", response)
    passed = check_submit_response(response)
    print("PASS" if passed else "FAIL")
    return passed


def run_queue_test(client):
    response = client.get(f"{BASE_URL}/api/queue")
    print_response("GET /api/queue", response)

    passed = False
    if response.status_code == 200:
        try:
            rows = response.json()
            passed = isinstance(rows, list) and len(rows) <= 10
            if passed and rows:
                passed = EXPECTED_SUBMIT_FIELDS.issubset(rows[0].keys())
        except ValueError:
            passed = False

    print("PASS" if passed else "FAIL")
    return passed


def main():
    results = []

    with httpx.Client(timeout=10.0) as client:
        results.append(
            run_submit_test(client, "https://paypal-secure-login.xyz/verify")
        )
        results.append(run_submit_test(client, "https://google.com"))
        results.append(run_queue_test(client))

    print(f"\n{sum(results)}/{len(results)} checks passed")


if __name__ == "__main__":
    main()
