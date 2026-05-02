import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent.parent / "data" / "threats.db"


def get_connection():
    DB_PATH.parent.mkdir(exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS cves (
            id          TEXT PRIMARY KEY,
            published   TEXT NOT NULL,
            description TEXT,
            cvss_score  REAL,
            severity    TEXT,
            cwe         TEXT
        );

        CREATE TABLE IF NOT EXISTS news (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            title     TEXT,
            link      TEXT UNIQUE,
            published TEXT,
            source    TEXT,
            summary   TEXT
        );

        CREATE TABLE IF NOT EXISTS exploits (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT,
            link        TEXT UNIQUE,
            published   TEXT,
            cve_id      TEXT,
            platform    TEXT,
            exploit_type TEXT
        );
    """)
    conn.commit()
    conn.close()


def insert_cve(record: dict):
    conn = get_connection()
    conn.execute(
        "INSERT OR IGNORE INTO cves (id, published, description, cvss_score, severity, cwe) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (record["id"], record["published"], record["description"],
         record.get("cvss_score"), record.get("severity"), record.get("cwe")),
    )
    conn.commit()
    conn.close()


def insert_news(record: dict):
    conn = get_connection()
    conn.execute(
        "INSERT OR IGNORE INTO news (title, link, published, source, summary) "
        "VALUES (?, ?, ?, ?, ?)",
        (record["title"], record["link"], record["published"],
         record["source"], record.get("summary", "")),
    )
    conn.commit()
    conn.close()


def get_cves(limit: int = None):
    conn = get_connection()
    query = "SELECT id, published, description, cvss_score, severity, cwe FROM cves ORDER BY published DESC"
    if limit:
        query += f" LIMIT {limit}"
    rows = conn.execute(query).fetchall()
    conn.close()
    return rows


def get_cve_stats():
    conn = get_connection()
    rows = conn.execute(
        "SELECT severity, COUNT(*) FROM cves GROUP BY severity"
    ).fetchall()
    conn.close()
    return {row[0] or "UNKNOWN": row[1] for row in rows}


def get_daily_counts():
    conn = get_connection()
    rows = conn.execute(
        "SELECT substr(published, 1, 10) AS day, COUNT(*) AS cnt "
        "FROM cves GROUP BY day ORDER BY day"
    ).fetchall()
    conn.close()
    return rows


def get_news(limit: int = 20):
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, title, link, published, source, summary FROM news ORDER BY published DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return rows


def insert_exploit(record: dict):
    conn = get_connection()
    conn.execute(
        "INSERT OR IGNORE INTO exploits (title, link, published, cve_id, platform, exploit_type) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (record["title"], record["link"], record["published"],
         record.get("cve_id", ""), record.get("platform", ""), record.get("exploit_type", "")),
    )
    conn.commit()
    conn.close()


def get_exploits(limit: int = 50):
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, title, link, published, cve_id, platform, exploit_type "
        "FROM exploits ORDER BY published DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return rows


def get_recent_critical_count(hours: int = 24) -> int:
    from datetime import datetime, timedelta, timezone
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
    conn = get_connection()
    count = conn.execute(
        "SELECT COUNT(*) FROM cves WHERE severity = 'CRITICAL' AND published >= ?",
        (cutoff,),
    ).fetchone()[0]
    conn.close()
    return count


def get_total_counts():
    conn = get_connection()
    cve_count     = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    news_count    = conn.execute("SELECT COUNT(*) FROM news").fetchone()[0]
    exploit_count = conn.execute("SELECT COUNT(*) FROM exploits").fetchone()[0]
    conn.close()
    return cve_count, news_count, exploit_count
