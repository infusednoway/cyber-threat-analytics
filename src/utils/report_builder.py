import json
from datetime import datetime, timedelta
from typing import Optional

from src.database.db import get_connection, get_cves, get_news, get_exploits
from src.models.predictor import get_severity_distribution, get_weekly_growth
from src.utils.statistics import (
    get_top_cwe, get_cvss_distribution, get_exploit_type_stats,
    get_exploit_platform_stats, get_news_source_stats, get_summary_stats,
)


def _date_range_filter(rows: list[dict], date_from: str, date_to: str,
                       field: str = "published") -> list[dict]:
    if not date_from and not date_to:
        return rows
    result = []
    for r in rows:
        val = r.get(field) or ""
        if date_from and val < date_from:
            continue
        if date_to and val > date_to + "Z":
            continue
        result.append(r)
    return result


def _severity_breakdown(rows: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for r in rows:
        sev = (r.get("severity") or "UNKNOWN").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _top_cvss(rows: list[dict], n: int = 10) -> list[dict]:
    scored = [r for r in rows if r.get("cvss_score")]
    scored.sort(key=lambda x: float(x["cvss_score"] or 0), reverse=True)
    return [
        {"id": r["id"], "cvss_score": r["cvss_score"],
         "severity": r.get("severity", "UNKNOWN"),
         "description": (r.get("description") or "")[:120]}
        for r in scored[:n]
    ]


def _cve_daily_counts(rows: list[dict]) -> list[dict]:
    counts: dict[str, int] = {}
    for r in rows:
        day = (r.get("published") or "")[:10]
        if day:
            counts[day] = counts.get(day, 0) + 1
    return [{"date": d, "count": c} for d, c in sorted(counts.items())]


def build_executive_summary(date_from: str = "", date_to: str = "") -> dict:
    summary = get_summary_stats()
    growth  = get_weekly_growth()
    sev     = get_severity_distribution()
    return {
        "generated_at": datetime.utcnow().isoformat(),
        "period":       {"from": date_from or "all time", "to": date_to or "now"},
        "totals": {
            "cves":     summary.get("total_cves", 0),
            "exploits": summary.get("total_exploits", 0),
            "news":     summary.get("total_news", 0),
        },
        "severity_distribution": sev,
        "weekly_growth_pct":     growth,
        "risk_level": (
            "CRITICAL" if sev.get("CRITICAL", 0) > 50
            else "HIGH"   if sev.get("HIGH", 0)     > 100
            else "MEDIUM" if sev.get("MEDIUM", 0)   > 200
            else "LOW"
        ),
    }


def build_cve_section(date_from: str = "", date_to: str = "",
                      limit: int = 500) -> dict:
    rows = get_cves(limit=limit)
    rows = _date_range_filter(rows, date_from, date_to, field="published")
    return {
        "total":             len(rows),
        "severity_breakdown": _severity_breakdown(rows),
        "top_by_cvss":       _top_cvss(rows, 10),
        "daily_counts":      _cve_daily_counts(rows),
        "top_cwe":           get_top_cwe(10),
        "cvss_distribution": get_cvss_distribution(),
    }


def build_exploit_section(limit: int = 200) -> dict:
    rows = get_exploits(limit=limit)
    by_type: dict[str, int] = {}
    by_platform: dict[str, int] = {}
    linked = 0
    for r in rows:
        t = r.get("exploit_type") or "unknown"
        p = r.get("platform")     or "unknown"
        by_type[t]     = by_type.get(t, 0) + 1
        by_platform[p] = by_platform.get(p, 0) + 1
        if r.get("cve_id"):
            linked += 1
    return {
        "total":        len(rows),
        "linked_cves":  linked,
        "by_type":      sorted(by_type.items(),     key=lambda x: x[1], reverse=True),
        "by_platform":  sorted(by_platform.items(), key=lambda x: x[1], reverse=True)[:10],
        "type_stats":   get_exploit_type_stats(),
        "platform_stats": get_exploit_platform_stats(),
    }


def build_news_section(limit: int = 200) -> dict:
    rows = get_news(limit=limit)
    by_source: dict[str, int] = {}
    for r in rows:
        src = r.get("source") or "unknown"
        by_source[src] = by_source.get(src, 0) + 1
    recent = sorted(rows, key=lambda x: x.get("published") or "", reverse=True)[:5]
    return {
        "total":          len(rows),
        "by_source":      sorted(by_source.items(), key=lambda x: x[1], reverse=True),
        "recent_items":   [
            {"title": r.get("title", ""), "source": r.get("source", ""),
             "published": r.get("published", ""), "url": r.get("url", "")}
            for r in recent
        ],
        "source_stats":   get_news_source_stats(),
    }


def build_trend_section() -> dict:
    from src.models.predictor import get_timeline_data, predict_next_days
    timeline    = get_timeline_data()
    predictions = predict_next_days(14)
    peak = max(timeline, key=lambda x: x["count"], default={})
    return {
        "timeline_points":   len(timeline),
        "peak_day":          peak.get("date", "N/A"),
        "peak_count":        peak.get("count", 0),
        "next_14_days":      predictions,
        "weekly_growth_pct": get_weekly_growth(),
    }


def build_anomaly_section() -> dict:
    from src.models.anomaly import AnomalyDetector
    detector  = AnomalyDetector(window=14, threshold=2.0)
    anomalies = detector.detect()
    return {
        "total_anomalies": len(anomalies),
        "recent":          anomalies[:10],
    }


def build_nlp_section() -> dict:
    from src.models.nlp_analyzer import (
        get_threat_type_distribution, get_product_exposure,
        get_top_keywords_across_cves,
    )
    return {
        "threat_type_distribution": get_threat_type_distribution(500),
        "top_exposed_products":     get_product_exposure(500)[:10],
        "top_keywords":             get_top_keywords_across_cves(500, 20),
    }


def build_full_report(date_from: str = "", date_to: str = "",
                      include_nlp: bool = True,
                      include_anomalies: bool = True) -> dict:
    report: dict = {
        "meta": {
            "generated_at": datetime.utcnow().isoformat(),
            "date_from":    date_from or "all time",
            "date_to":      date_to   or "now",
        },
        "executive_summary": build_executive_summary(date_from, date_to),
        "cve_analysis":      build_cve_section(date_from, date_to),
        "exploit_analysis":  build_exploit_section(),
        "news_analysis":     build_news_section(),
        "trend_analysis":    build_trend_section(),
    }
    if include_anomalies:
        report["anomaly_analysis"] = build_anomaly_section()
    if include_nlp:
        report["nlp_analysis"] = build_nlp_section()
    return report


def build_weekly_digest() -> dict:
    week_ago  = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")
    today_str = datetime.utcnow().strftime("%Y-%m-%d")
    return build_full_report(date_from=week_ago, date_to=today_str,
                             include_nlp=True, include_anomalies=True)


def build_monthly_digest() -> dict:
    month_ago = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%d")
    today_str = datetime.utcnow().strftime("%Y-%m-%d")
    return build_full_report(date_from=month_ago, date_to=today_str,
                             include_nlp=True, include_anomalies=True)


def compare_periods(days_a: int = 7, days_b: int = 14) -> dict:
    now    = datetime.utcnow()
    rows   = get_cves(limit=2000)

    def _window(start_days: int, end_days: int) -> list[dict]:
        start = (now - timedelta(days=start_days)).strftime("%Y-%m-%d")
        end   = (now - timedelta(days=end_days)).strftime("%Y-%m-%d")
        return [r for r in rows
                if end <= (r.get("published") or "")[:10] <= start]

    period_a = _window(days_b, days_a)
    period_b = _window(days_a, 0)

    def _stats(r_list: list[dict]) -> dict:
        sev = _severity_breakdown(r_list)
        return {"total": len(r_list), "severity": sev}

    return {
        "period_a": {
            "label":  f"prev {days_b - days_a} days",
            "stats":  _stats(period_a),
        },
        "period_b": {
            "label":  f"last {days_a} days",
            "stats":  _stats(period_b),
        },
        "delta_total": len(period_b) - len(period_a),
    }


def get_severity_heatmap(weeks: int = 8) -> list[dict]:
    rows  = get_cves(limit=2000)
    now   = datetime.utcnow()
    result = []
    for w in range(weeks, 0, -1):
        start = (now - timedelta(weeks=w)).strftime("%Y-%m-%d")
        end   = (now - timedelta(weeks=w - 1)).strftime("%Y-%m-%d")
        bucket = [r for r in rows
                  if start <= (r.get("published") or "")[:10] < end]
        sev = _severity_breakdown(bucket)
        result.append({
            "week_start": start,
            "week_end":   end,
            "total":      len(bucket),
            **sev,
        })
    return result


def get_cvss_percentiles(bins: int = 10) -> list[dict]:
    rows   = get_cves(limit=2000)
    scores = [float(r["cvss_score"]) for r in rows if r.get("cvss_score")]
    if not scores:
        return []
    step   = 10.0 / bins
    result = []
    for i in range(bins):
        low  = round(i * step, 1)
        high = round((i + 1) * step, 1)
        cnt  = sum(1 for s in scores if low <= s < high)
        result.append({"range": f"{low}-{high}", "count": cnt})
    return result


def get_report_cover_data(title: str, author: str = "Analyst") -> dict:
    summary = build_executive_summary()
    return {
        "title":         title,
        "author":        author,
        "generated_at":  datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "total_cves":    summary["totals"]["cves"],
        "total_exploits": summary["totals"]["exploits"],
        "risk_level":    summary["risk_level"],
        "weekly_growth": summary["weekly_growth_pct"],
    }


def summarize_for_alert(cve_id: str) -> Optional[str]:
    from src.models.nlp_analyzer import analyze_cve_text
    data = analyze_cve_text(cve_id)
    if not data:
        return None
    parts = [
        f"{cve_id}: severity={data['severity']}, CVSS={data['cvss_score']}.",
        f"Threat types: {', '.join(data['threat_types'])}.",
    ]
    if data["products"]:
        parts.append(f"Affected: {', '.join(data['products'][:5])}.")
    top_kw = [k for k, _ in data["keywords"][:5]]
    if top_kw:
        parts.append(f"Keywords: {', '.join(top_kw)}.")
    return " ".join(parts)
