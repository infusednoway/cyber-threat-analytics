"""
Composite risk scoring for CVEs.

Score = weighted sum of:
  - CVSS severity band  (0-40 pts)
  - Has known exploit   (0-25 pts)
  - Threat type weight  (0-20 pts)
  - Recency bonus       (0-10 pts)
  - Keyword signals     (0-5  pts)
Total maximum: 100 pts
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta
from typing import Optional

from src.database.db import get_cves, get_exploits, get_connection


# ──────────────────── weight tables ──────────────────────────────────────────

_SEVERITY_SCORE = {
    "CRITICAL": 40,
    "HIGH":     30,
    "MEDIUM":   15,
    "LOW":       5,
    "UNKNOWN":   0,
}

_THREAT_WEIGHT = {
    "remote_code_execution": 20,
    "zero_day":              18,
    "privilege_escalation":  14,
    "sql_injection":         12,
    "buffer_overflow":       12,
    "authentication_bypass": 11,
    "xss":                    8,
    "supply_chain":          10,
    "dos":                    7,
    "information_disclosure": 6,
    "other":                  2,
}

_HIGH_SIGNAL_WORDS = [
    "actively exploited", "in the wild", "no patch", "zero-day",
    "critical infrastructure", "ransomware", "nation-state",
]

_LOW_SIGNAL_WORDS = [
    "requires physical", "local only", "user interaction required",
    "low complexity attack",
]


# ──────────────────── sub-scorers ─────────────────────────────────────────────

def _cvss_to_pts(cvss_score: Optional[float]) -> float:
    if cvss_score is None:
        return 0.0
    # map 0-10 to 0-40 using a slight curve for values above 9
    return min(40.0, cvss_score * 4.0)


def _severity_pts(severity: str) -> int:
    return _SEVERITY_SCORE.get((severity or "UNKNOWN").upper(), 0)


def _exploit_pts(cve_id: str, exploit_index: set[str]) -> int:
    return 25 if cve_id in exploit_index else 0


def _threat_type_pts(threat_types: list[str]) -> int:
    return max((_THREAT_WEIGHT.get(t, 0) for t in threat_types), default=0)


def _recency_pts(published: Optional[str], max_days: int = 90) -> float:
    if not published:
        return 0.0
    try:
        pub = datetime.fromisoformat(published.replace("Z", "+00:00").replace(" ", "T"))
        pub = pub.replace(tzinfo=None)
    except ValueError:
        try:
            pub = datetime.strptime(published[:10], "%Y-%m-%d")
        except ValueError:
            return 0.0
    age_days = (datetime.utcnow() - pub).days
    if age_days < 0:
        return 10.0
    return max(0.0, 10.0 * (1 - age_days / max_days))


def _keyword_pts(description: str) -> float:
    desc = (description or "").lower()
    score = 0.0
    for w in _HIGH_SIGNAL_WORDS:
        if w in desc:
            score += 1.5
    for w in _LOW_SIGNAL_WORDS:
        if w in desc:
            score -= 1.0
    return max(0.0, min(5.0, score))


# ──────────────────── main scorer ─────────────────────────────────────────────

def score_cve(row: dict, exploit_index: set[str],
              threat_types: Optional[list[str]] = None) -> dict:
    """Return a full scoring breakdown for a single CVE row."""
    from src.models.nlp_analyzer import classify_threat_type

    cve_id      = row.get("id", "")
    severity    = (row.get("severity") or "UNKNOWN").upper()
    cvss_raw    = row.get("cvss_score")
    cvss_score  = float(cvss_raw) if cvss_raw else None
    description = row.get("description") or ""
    published   = row.get("published") or ""

    if threat_types is None:
        threat_types = classify_threat_type(description)

    pts_severity  = _severity_pts(severity)
    pts_cvss      = _cvss_to_pts(cvss_score)
    pts_exploit   = _exploit_pts(cve_id, exploit_index)
    pts_threat    = _threat_type_pts(threat_types)
    pts_recency   = _recency_pts(published)
    pts_keywords  = _keyword_pts(description)

    # blend severity and cvss: take higher, not sum
    pts_sev_final = max(pts_severity, pts_cvss * 0.9)

    total = pts_sev_final + pts_exploit + pts_threat + pts_recency + pts_keywords
    total = min(100.0, total)

    label = (
        "CRITICAL" if total >= 75
        else "HIGH"   if total >= 55
        else "MEDIUM" if total >= 35
        else "LOW"
    )

    return {
        "cve_id":       cve_id,
        "risk_score":   round(total, 2),
        "risk_label":   label,
        "components": {
            "severity":    round(pts_sev_final, 2),
            "exploit":     pts_exploit,
            "threat_type": pts_threat,
            "recency":     round(pts_recency, 2),
            "keywords":    round(pts_keywords, 2),
        },
        "threat_types": threat_types,
        "severity":     severity,
        "cvss_score":   cvss_score,
        "published":    published,
    }


# ──────────────────── batch API ───────────────────────────────────────────────

def _build_exploit_index(limit: int = 2000) -> set[str]:
    exploits = get_exploits(limit=limit)
    return {e["cve_id"] for e in exploits if e.get("cve_id")}


def score_all_cves(limit: int = 1000) -> list[dict]:
    rows          = get_cves(limit=limit)
    exploit_index = _build_exploit_index()
    results       = []
    for row in rows:
        if not (row.get("description") or row.get("cvss_score")):
            continue
        results.append(score_cve(row, exploit_index))
    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return results


def get_top_risk_cves(n: int = 20, limit: int = 1000) -> list[dict]:
    return score_all_cves(limit=limit)[:n]


def get_risk_distribution(limit: int = 1000) -> dict[str, int]:
    scored = score_all_cves(limit=limit)
    dist: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in scored:
        dist[r["risk_label"]] = dist.get(r["risk_label"], 0) + 1
    return dist


def get_risk_score_for_cve(cve_id: str) -> Optional[dict]:
    conn = get_connection()
    row  = conn.execute(
        "SELECT id, description, severity, cvss_score, published "
        "FROM cves WHERE id = ?", (cve_id,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    exploit_index = _build_exploit_index()
    return score_cve(dict(row), exploit_index)


# ──────────────────── trend risk ──────────────────────────────────────────────

def get_risk_trend(days: int = 30) -> list[dict]:
    """Daily average risk score for recent CVEs."""
    rows          = get_cves(limit=2000)
    exploit_index = _build_exploit_index()
    cutoff        = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")

    daily: dict[str, list[float]] = {}
    for row in rows:
        pub = (row.get("published") or "")[:10]
        if pub < cutoff:
            continue
        s = score_cve(row, exploit_index)
        daily.setdefault(pub, []).append(s["risk_score"])

    return [
        {"date": d, "avg_risk": round(sum(v) / len(v), 2), "count": len(v)}
        for d, v in sorted(daily.items())
    ]


def get_component_averages(limit: int = 500) -> dict[str, float]:
    """Average contribution of each scoring component."""
    rows          = get_cves(limit=limit)
    exploit_index = _build_exploit_index()
    totals: dict[str, float] = {
        "severity": 0, "exploit": 0, "threat_type": 0,
        "recency": 0, "keywords": 0,
    }
    n = 0
    for row in rows:
        s = score_cve(row, exploit_index)
        for k in totals:
            totals[k] += s["components"][k]
        n += 1
    if n == 0:
        return totals
    return {k: round(v / n, 3) for k, v in totals.items()}


def cluster_by_risk(limit: int = 500) -> dict[str, list[str]]:
    """Group CVE IDs by risk label for quick lookup."""
    scored  = score_all_cves(limit=limit)
    buckets: dict[str, list[str]] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for r in scored:
        buckets[r["risk_label"]].append(r["cve_id"])
    return buckets


def get_high_risk_with_exploit(limit: int = 500) -> list[dict]:
    """CVEs that are both high-scored AND have a known public exploit."""
    scored = score_all_cves(limit=limit)
    return [r for r in scored
            if r["components"]["exploit"] > 0 and r["risk_score"] >= 55]


def explain_score(cve_id: str) -> Optional[str]:
    """Human-readable explanation of why a CVE got its score."""
    data = get_risk_score_for_cve(cve_id)
    if not data:
        return None
    c = data["components"]
    lines = [
        f"{cve_id} — Risk score: {data['risk_score']}/100 ({data['risk_label']})",
        f"  Severity/CVSS:  {c['severity']:.1f} pts  (raw severity={data['severity']}, CVSS={data['cvss_score']})",
        f"  Known exploit:  {c['exploit']} pts",
        f"  Threat type:    {c['threat_type']} pts  ({', '.join(data['threat_types'])})",
        f"  Recency:        {c['recency']:.1f} pts  (published={data['published'][:10]})",
        f"  Text signals:   {c['keywords']:.1f} pts",
    ]
    return "\n".join(lines)
