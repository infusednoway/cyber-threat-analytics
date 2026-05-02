import time
import requests
from datetime import datetime, timedelta

from src.database.db import insert_cve

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000


def _parse_vulnerability(vuln: dict) -> dict:
    cve = vuln.get("cve", {})

    descriptions = cve.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

    cvss_score = None
    severity = "UNKNOWN"
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            data = metrics[key][0]
            cvss_data = data.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity") or data.get("baseSeverity", "UNKNOWN")
            break

    weaknesses = cve.get("weaknesses", [])
    cwe = ""
    if weaknesses:
        descs = weaknesses[0].get("description", [])
        cwe = descs[0].get("value", "") if descs else ""

    return {
        "id": cve.get("id", ""),
        "published": cve.get("published", ""),
        "description": description[:500],
        "cvss_score": cvss_score,
        "severity": severity.upper() if severity else "UNKNOWN",
        "cwe": cwe,
    }


def fetch_cves(days_back: int = 90, max_results: int = 2000) -> list:
    end_dt = datetime.utcnow()
    start_dt = end_dt - timedelta(days=days_back)

    params = {
        "pubStartDate": start_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": min(PAGE_SIZE, max_results),
        "startIndex": 0,
    }

    collected = []
    while True:
        try:
            resp = requests.get(NVD_API_URL, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            print(f"[NVD] Ошибка запроса: {exc}")
            break

        vulnerabilities = data.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            record = _parse_vulnerability(vuln)
            if record["id"]:
                insert_cve(record)
                collected.append(record)

        total = data.get("totalResults", 0)
        params["startIndex"] += len(vulnerabilities)

        if params["startIndex"] >= min(total, max_results) or not vulnerabilities:
            break

        time.sleep(0.6)

    print(f"[NVD] Загружено {len(collected)} CVE за последние {days_back} дней")
    return collected
