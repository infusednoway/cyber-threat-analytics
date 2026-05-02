from collections import Counter
from datetime import datetime, timedelta

from src.database.db import get_connection


def get_cve_by_severity_over_time(days: int = 90) -> dict:
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    conn = get_connection()
    rows = conn.execute(
        "SELECT substr(published,1,10) as day, severity, COUNT(*) as cnt "
        "FROM cves WHERE published >= ? GROUP BY day, severity ORDER BY day",
        (cutoff,)
    ).fetchall()
    conn.close()

    result: dict[str, dict] = {}
    for row in rows:
        day, sev, cnt = row[0], row[1] or "UNKNOWN", row[2]
        if day not in result:
            result[day] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "UNKNOWN": 0}
        result[day][sev] = result[day].get(sev, 0) + cnt
    return result


def get_top_cwe(limit: int = 10) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT cwe, COUNT(*) as cnt FROM cves "
        "WHERE cwe IS NOT NULL AND cwe != '' "
        "GROUP BY cwe ORDER BY cnt DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [{"cwe": r[0], "count": r[1]} for r in rows]


def get_cvss_distribution() -> dict:
    conn = get_connection()
    rows = conn.execute(
        "SELECT cvss_score FROM cves WHERE cvss_score IS NOT NULL"
    ).fetchall()
    conn.close()

    buckets = {"0-3.9": 0, "4.0-6.9": 0, "7.0-8.9": 0, "9.0-10.0": 0}
    for (score,) in rows:
        if score < 4.0:
            buckets["0-3.9"] += 1
        elif score < 7.0:
            buckets["4.0-6.9"] += 1
        elif score < 9.0:
            buckets["7.0-8.9"] += 1
        else:
            buckets["9.0-10.0"] += 1
    return buckets


def get_daily_avg(days: int = 30) -> float:
    conn = get_connection()
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    rows = conn.execute(
        "SELECT COUNT(*) as cnt FROM cves WHERE published >= ?", (cutoff,)
    ).fetchone()
    conn.close()
    total = rows[0] if rows else 0
    return round(total / days, 1)


def get_exploit_platform_stats() -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT platform, COUNT(*) as cnt FROM exploits "
        "WHERE platform IS NOT NULL AND platform != '' "
        "GROUP BY platform ORDER BY cnt DESC"
    ).fetchall()
    conn.close()
    return [{"platform": r[0], "count": r[1]} for r in rows]


def get_exploit_type_stats() -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT exploit_type, COUNT(*) as cnt FROM exploits "
        "GROUP BY exploit_type ORDER BY cnt DESC"
    ).fetchall()
    conn.close()
    return [{"type": r[0], "count": r[1]} for r in rows]


def get_news_source_stats() -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT source, COUNT(*) as cnt FROM news GROUP BY source ORDER BY cnt DESC"
    ).fetchall()
    conn.close()
    return [{"source": r[0], "count": r[1]} for r in rows]


def get_peak_day() -> dict:
    conn = get_connection()
    row = conn.execute(
        "SELECT substr(published,1,10) as day, COUNT(*) as cnt "
        "FROM cves GROUP BY day ORDER BY cnt DESC LIMIT 1"
    ).fetchone()
    conn.close()
    if row:
        return {"date": row[0], "count": row[1]}
    return {"date": "—", "count": 0}


def get_severity_percentages() -> dict:
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    rows  = conn.execute(
        "SELECT severity, COUNT(*) FROM cves GROUP BY severity"
    ).fetchall()
    conn.close()
    if not total:
        return {}
    return {(r[0] or "UNKNOWN"): round(r[1] / total * 100, 1) for r in rows}


def get_cves_with_exploits() -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT c.id, c.severity, c.cvss_score, e.exploit_type, e.platform "
        "FROM cves c JOIN exploits e ON c.id = e.cve_id "
        "ORDER BY c.cvss_score DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return [
        {"cve_id": r[0], "severity": r[1], "cvss_score": r[2],
         "exploit_type": r[3], "platform": r[4]}
        for r in rows
    ]


def get_unread_alerts_count() -> int:
    conn = get_connection()
    count = conn.execute(
        "SELECT COUNT(*) FROM alert_log WHERE is_read = 0"
    ).fetchone()[0]
    conn.close()
    return count


def get_summary_stats() -> dict:
    conn = get_connection()
    total_cves     = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    total_exploits = conn.execute("SELECT COUNT(*) FROM exploits").fetchone()[0]
    total_news     = conn.execute("SELECT COUNT(*) FROM news").fetchone()[0]
    total_users    = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    total_reports  = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    unread_alerts  = conn.execute("SELECT COUNT(*) FROM alert_log WHERE is_read=0").fetchone()[0]
    conn.close()
    return {
        "total_cves":     total_cves,
        "total_exploits": total_exploits,
        "total_news":     total_news,
        "total_users":    total_users,
        "total_reports":  total_reports,
        "unread_alerts":  unread_alerts,
        "daily_avg":      get_daily_avg(30),
        "peak_day":       get_peak_day(),
    }
