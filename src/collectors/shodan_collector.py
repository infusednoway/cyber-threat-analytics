from __future__ import annotations

import os
import time
import logging
from datetime import datetime
from typing import Optional

import requests

logger = logging.getLogger(__name__)

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
SHODAN_BASE    = "https://api.shodan.io"

_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "CyberThreatAnalytics/1.0"})


def _api_get(path: str, params: dict = None, timeout: int = 20) -> Optional[dict]:
    if not SHODAN_API_KEY:
        logger.debug("SHODAN_API_KEY not set — skipping real request for %s", path)
        return None
    url = SHODAN_BASE + path
    p   = {"key": SHODAN_API_KEY}
    if params:
        p.update(params)
    try:
        r = _SESSION.get(url, params=p, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 429:
            logger.warning("Shodan rate-limited, sleeping 10s")
            time.sleep(10)
        else:
            logger.error("Shodan HTTP error: %s", exc)
        return None
    except Exception as exc:
        logger.error("Shodan request failed: %s", exc)
        return None


def get_host_info(ip: str) -> Optional[dict]:
    data = _api_get(f"/shodan/host/{ip}")
    if not data:
        return _mock_host(ip)
    return _parse_host(data)


def _parse_host(raw: dict) -> dict:
    ports   = raw.get("ports", [])
    vulns   = raw.get("vulns", {})
    tags    = raw.get("tags", [])
    hostnames = raw.get("hostnames", [])
    return {
        "ip":         raw.get("ip_str", ""),
        "org":        raw.get("org", ""),
        "country":    raw.get("country_name", ""),
        "city":       raw.get("city", ""),
        "isp":        raw.get("isp", ""),
        "os":         raw.get("os", ""),
        "ports":      ports,
        "open_ports": len(ports),
        "vulns":      list(vulns.keys()),
        "vuln_count": len(vulns),
        "tags":       tags,
        "hostnames":  hostnames,
        "last_update": raw.get("last_update", ""),
    }


def _mock_host(ip: str) -> dict:
    return {
        "ip":         ip,
        "org":        "Mock ISP",
        "country":    "Mock Country",
        "city":       "Mock City",
        "isp":        "Mock ISP",
        "os":         None,
        "ports":      [80, 443, 22],
        "open_ports": 3,
        "vulns":      [],
        "vuln_count": 0,
        "tags":       [],
        "hostnames":  [],
        "last_update": datetime.utcnow().isoformat(),
        "_mock":      True,
    }


def search_hosts_for_cve(cve_id: str, limit: int = 20) -> list[dict]:
    query = f"vuln:{cve_id}"
    data  = _api_get("/shodan/host/search",
                     params={"query": query, "facets": "country,port", "page": 1})
    if not data:
        return _mock_cve_hosts(cve_id, limit)

    hosts = []
    for match in (data.get("matches") or [])[:limit]:
        hosts.append({
            "ip":       match.get("ip_str", ""),
            "port":     match.get("port"),
            "org":      match.get("org", ""),
            "country":  (match.get("location") or {}).get("country_name", ""),
            "product":  match.get("product", ""),
            "version":  match.get("version", ""),
            "cve_id":   cve_id,
        })
    return hosts


def _mock_cve_hosts(cve_id: str, n: int = 10) -> list[dict]:
    import random
    random.seed(hash(cve_id) & 0xFFFFFF)
    countries = ["United States", "Germany", "China", "Russia",
                 "Brazil", "India", "France", "Netherlands"]
    return [
        {
            "ip":      f"192.0.2.{random.randint(1, 254)}",
            "port":    random.choice([80, 443, 22, 3306, 8080, 25]),
            "org":     f"Mock Org {i}",
            "country": random.choice(countries),
            "product": "Mock Product",
            "version": "1.0",
            "cve_id":  cve_id,
            "_mock":   True,
        }
        for i in range(min(n, 10))
    ]


def get_vulnerability_facets(cve_id: str) -> dict:
    data = _api_get("/shodan/host/search",
                    params={"query": f"vuln:{cve_id}",
                            "facets": "country:10,port:10", "page": 1})
    if not data:
        return _mock_facets(cve_id)

    facets = data.get("facets", {})
    return {
        "cve_id":    cve_id,
        "total":     data.get("total", 0),
        "countries": [{"name": f["value"], "count": f["count"]}
                      for f in (facets.get("country") or [])],
        "ports":     [{"port": f["value"], "count": f["count"]}
                      for f in (facets.get("port") or [])],
    }


def _mock_facets(cve_id: str) -> dict:
    return {
        "cve_id":    cve_id,
        "total":     0,
        "countries": [],
        "ports":     [],
        "_mock":     True,
    }


def search_by_product(product: str, limit: int = 50) -> list[dict]:
    data = _api_get("/shodan/host/search",
                    params={"query": f"product:{product}", "page": 1})
    if not data:
        return []
    hosts = []
    for match in (data.get("matches") or [])[:limit]:
        hosts.append({
            "ip":      match.get("ip_str", ""),
            "port":    match.get("port"),
            "org":     match.get("org", ""),
            "country": (match.get("location") or {}).get("country_name", ""),
            "product": match.get("product", product),
            "version": match.get("version", ""),
            "vulns":   list((match.get("vulns") or {}).keys()),
        })
    return hosts


def count_exposed_hosts(query: str) -> int:
    data = _api_get("/shodan/host/count", params={"query": query})
    if not data:
        return 0
    return data.get("total", 0)


def enrich_cve_with_exposure(cve_id: str) -> dict:
    facets = get_vulnerability_facets(cve_id)
    hosts  = search_hosts_for_cve(cve_id, limit=10)
    top_countries = sorted(facets.get("countries", []),
                           key=lambda x: x["count"], reverse=True)[:5]
    top_ports     = sorted(facets.get("ports", []),
                           key=lambda x: x["count"], reverse=True)[:5]
    return {
        "cve_id":          cve_id,
        "exposed_hosts":   facets.get("total", 0),
        "top_countries":   top_countries,
        "top_ports":       top_ports,
        "sample_hosts":    hosts[:5],
        "exposure_level":  (
            "CRITICAL" if facets.get("total", 0) > 10000
            else "HIGH"   if facets.get("total", 0) > 1000
            else "MEDIUM" if facets.get("total", 0) > 100
            else "LOW"
        ),
    }


def batch_enrich_cves(cve_ids: list[str]) -> list[dict]:
    results = []
    for cve_id in cve_ids:
        try:
            results.append(enrich_cve_with_exposure(cve_id))
            time.sleep(1.1)   # stay within Shodan's 1 req/s free tier
        except Exception as exc:
            logger.warning("Failed to enrich %s: %s", cve_id, exc)
    return results


def get_port_stats(ports: list[int] = None) -> list[dict]:
    if ports is None:
        ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080, 8443, 27017]
    if not SHODAN_API_KEY:
        import random
        random.seed(42)
        return [{"port": p, "count": random.randint(100_000, 50_000_000), "_mock": True}
                for p in ports]
    results = []
    for port in ports:
        cnt = count_exposed_hosts(f"port:{port}")
        results.append({"port": port, "count": cnt})
        time.sleep(0.5)
    return sorted(results, key=lambda x: x["count"], reverse=True)


def get_vulnerability_trend(cve_ids: list[str]) -> list[dict]:
    trend = []
    for cve_id in cve_ids:
        facets = get_vulnerability_facets(cve_id)
        trend.append({"cve_id": cve_id, "exposed": facets.get("total", 0)})
    return sorted(trend, key=lambda x: x["exposed"], reverse=True)


def get_api_status() -> dict:
    if not SHODAN_API_KEY:
        return {"status": "no_key", "message": "SHODAN_API_KEY environment variable not set"}
    data = _api_get("/api-info")
    if not data:
        return {"status": "error", "message": "Could not reach Shodan API"}
    return {
        "status":  "ok",
        "plan":    data.get("plan", "unknown"),
        "credits": data.get("query_credits", 0),
        "scan_credits": data.get("scan_credits", 0),
    }
