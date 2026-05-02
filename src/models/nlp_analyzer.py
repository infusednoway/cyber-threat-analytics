import re
from collections import Counter
from typing import Optional

from src.database.db import get_cves, get_news, get_connection

THREAT_KEYWORDS = {
    "remote_code_execution": [
        "remote code execution", "rce", "arbitrary code", "execute arbitrary",
        "code injection", "command injection", "os command",
    ],
    "sql_injection": [
        "sql injection", "sqli", "database injection", "blind sql",
        "union-based", "error-based sql",
    ],
    "xss": [
        "cross-site scripting", "xss", "reflected xss", "stored xss",
        "dom-based", "script injection",
    ],
    "privilege_escalation": [
        "privilege escalation", "local privilege", "root privilege",
        "elevation of privilege", "eop", "unauthorized access",
    ],
    "buffer_overflow": [
        "buffer overflow", "stack overflow", "heap overflow",
        "memory corruption", "out-of-bounds write", "stack-based buffer",
    ],
    "dos": [
        "denial of service", "dos attack", "ddos", "resource exhaustion",
        "infinite loop", "crash", "application crash",
    ],
    "information_disclosure": [
        "information disclosure", "data leakage", "sensitive data",
        "credential exposure", "path disclosure", "memory disclosure",
    ],
    "authentication_bypass": [
        "authentication bypass", "auth bypass", "improper authentication",
        "missing authentication", "weak authentication",
    ],
    "zero_day": [
        "zero-day", "0-day", "in the wild", "actively exploited",
        "wild exploitation", "no patch available",
    ],
    "supply_chain": [
        "supply chain", "dependency confusion", "malicious package",
        "typosquatting", "third-party library",
    ],
}

SEVERITY_KEYWORDS = {
    "critical": ["critical", "severe", "devastating", "catastrophic", "complete"],
    "high":     ["high", "significant", "serious", "major", "important"],
    "medium":   ["medium", "moderate", "limited", "partial"],
    "low":      ["low", "minor", "minimal", "negligible", "informational"],
}

PRODUCT_PATTERNS = [
    r"\bwindows\b", r"\blinux\b", r"\bapache\b", r"\bnginx\b",
    r"\bwordpress\b", r"\bphp\b", r"\bpython\b", r"\bjava\b",
    r"\bnode\.?js\b", r"\breact\b", r"\bangular\b", r"\bdjango\b",
    r"\bmysql\b", r"\bpostgres\b", r"\bmongodb\b", r"\bredis\b",
    r"\bopenssh\b", r"\bopenssl\b", r"\bchrome\b", r"\bfirefox\b",
    r"\bsafari\b", r"\bedge\b", r"\bios\b", r"\bandroid\b",
    r"\bmacos\b", r"\bkubernetes\b", r"\bdocker\b", r"\bjenkins\b",
]


def classify_threat_type(text: str) -> list[str]:
    text_lower = text.lower()
    found = []
    for threat_type, keywords in THREAT_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            found.append(threat_type)
    return found if found else ["other"]


def extract_products(text: str) -> list[str]:
    text_lower = text.lower()
    found = []
    for pattern in PRODUCT_PATTERNS:
        match = re.search(pattern, text_lower)
        if match:
            found.append(match.group().strip())
    return list(set(found))


def extract_keywords(text: str, top_n: int = 10) -> list[tuple[str, int]]:
    STOP_WORDS = {
        "the", "a", "an", "and", "or", "in", "on", "at", "to", "for",
        "of", "with", "that", "this", "is", "are", "was", "be", "by",
        "it", "its", "from", "as", "via", "can", "could", "may", "allows",
        "which", "when", "through", "within", "before", "after", "into",
        "not", "no", "has", "have", "been", "an", "if", "than", "then",
    }
    words  = re.findall(r"\b[a-zA-Z]{3,}\b", text.lower())
    counts = Counter(w for w in words if w not in STOP_WORDS)
    return counts.most_common(top_n)


def estimate_severity_from_text(text: str) -> str:
    text_lower = text.lower()
    scores = {}
    for level, keywords in SEVERITY_KEYWORDS.items():
        scores[level] = sum(1 for kw in keywords if kw in text_lower)
    best = max(scores, key=scores.get)
    return best.upper() if scores[best] > 0 else "UNKNOWN"


def analyze_cve_text(cve_id: str) -> Optional[dict]:
    conn = get_connection()
    row  = conn.execute(
        "SELECT id, description, severity, cvss_score FROM cves WHERE id = ?", (cve_id,)
    ).fetchone()
    conn.close()
    if not row:
        return None

    description = row["description"] or ""
    return {
        "cve_id":       row["id"],
        "severity":     row["severity"],
        "cvss_score":   row["cvss_score"],
        "threat_types": classify_threat_type(description),
        "products":     extract_products(description),
        "keywords":     extract_keywords(description, top_n=8),
        "text_severity": estimate_severity_from_text(description),
        "description_length": len(description),
    }


def batch_analyze_cves(limit: int = 500) -> list[dict]:
    rows = get_cves(limit=limit)
    results = []
    for row in rows:
        desc = row.get("description") or ""
        if not desc:
            continue
        results.append({
            "cve_id":       row["id"],
            "severity":     row.get("severity", "UNKNOWN"),
            "threat_types": classify_threat_type(desc),
            "products":     extract_products(desc),
        })
    return results


def get_threat_type_distribution(limit: int = 1000) -> dict[str, int]:
    rows = get_cves(limit=limit)
    distribution: dict[str, int] = {}
    for row in rows:
        desc  = row.get("description") or ""
        types = classify_threat_type(desc)
        for t in types:
            distribution[t] = distribution.get(t, 0) + 1
    return dict(sorted(distribution.items(), key=lambda x: x[1], reverse=True))


def get_product_exposure(limit: int = 1000) -> list[dict]:
    rows = get_cves(limit=limit)
    product_counts: dict[str, int] = {}
    product_severity: dict[str, list] = {}
    for row in rows:
        desc     = row.get("description") or ""
        products = extract_products(desc)
        sev      = row.get("severity") or "UNKNOWN"
        for p in products:
            product_counts[p]   = product_counts.get(p, 0) + 1
            product_severity.setdefault(p, []).append(sev)

    result = []
    for product, count in sorted(product_counts.items(), key=lambda x: x[1], reverse=True):
        sevs = product_severity[product]
        critical = sevs.count("CRITICAL")
        high     = sevs.count("HIGH")
        result.append({
            "product":  product,
            "total":    count,
            "critical": critical,
            "high":     high,
            "risk":     "HIGH" if critical > 0 else "MEDIUM" if high > 0 else "LOW",
        })
    return result[:20]


def analyze_news_sentiment(limit: int = 100) -> list[dict]:
    rows = get_news(limit=limit)
    results = []
    for row in rows:
        text = (row.get("title") or "") + " " + (row.get("summary") or "")
        results.append({
            "title":        row.get("title", ""),
            "source":       row.get("source", ""),
            "threat_types": classify_threat_type(text),
            "keywords":     [kw for kw, _ in extract_keywords(text, top_n=5)],
            "severity_hint": estimate_severity_from_text(text),
        })
    return results


def get_top_keywords_across_cves(limit: int = 500, top_n: int = 30) -> list[dict]:
    rows  = get_cves(limit=limit)
    all_text = " ".join(row.get("description") or "" for row in rows)
    kw    = extract_keywords(all_text, top_n=top_n)
    return [{"keyword": k, "count": c} for k, c in kw]
