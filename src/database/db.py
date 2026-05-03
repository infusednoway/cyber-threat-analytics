import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent.parent / "data" / "threats.db"


def get_connection():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS roles (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT
        );

        CREATE TABLE IF NOT EXISTS users (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT UNIQUE NOT NULL,
            email        TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role_id      INTEGER NOT NULL DEFAULT 3,
            is_active    INTEGER NOT NULL DEFAULT 1,
            created_at   TEXT NOT NULL DEFAULT (datetime('now')),
            last_login   TEXT,
            FOREIGN KEY (role_id) REFERENCES roles(id)
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT PRIMARY KEY,
            user_id    INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

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
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            title        TEXT,
            link         TEXT UNIQUE,
            published    TEXT,
            cve_id       TEXT,
            platform     TEXT,
            exploit_type TEXT
        );

        CREATE TABLE IF NOT EXISTS alert_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            level      TEXT NOT NULL,
            message    TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            is_read    INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS reports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT NOT NULL,
            created_by  INTEGER,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            date_from   TEXT,
            date_to     TEXT,
            total_cves  INTEGER,
            critical    INTEGER,
            high        INTEGER,
            medium      INTEGER,
            low         INTEGER,
            notes       TEXT,
            FOREIGN KEY (created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS watchlist (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            cve_id     TEXT NOT NULL,
            added_at   TEXT NOT NULL DEFAULT (datetime('now')),
            notes      TEXT,
            UNIQUE(user_id, cve_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS tags (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            color TEXT NOT NULL DEFAULT '#58a6ff'
        );

        CREATE TABLE IF NOT EXISTS cve_tags (
            cve_id TEXT NOT NULL,
            tag_id INTEGER NOT NULL,
            PRIMARY KEY (cve_id, tag_id),
            FOREIGN KEY (tag_id) REFERENCES tags(id)
        );

        INSERT OR IGNORE INTO roles (id, name, description)
        VALUES
            (1, 'admin',   'Полный доступ: управление пользователями и системой'),
            (2, 'analyst', 'Доступ к аналитике, отчётам и watchlist'),
            (3, 'viewer',  'Только просмотр данных');

        INSERT OR IGNORE INTO tags (name, color)
        VALUES
            ('ransomware',  '#f85149'),
            ('zero-day',    '#e3b341'),
            ('phishing',    '#d2a8ff'),
            ('patch-available', '#3fb950'),
            ('critical-infra',  '#f0883e');
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


def get_cves(limit: int = None, severity: str = None, search: str = None):
    conn = get_connection()
    where, params = [], []
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if search:
        where.append("(id LIKE ? OR description LIKE ?)")
        params += [f"%{search}%", f"%{search}%"]
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    limit_clause = f"LIMIT {limit}" if limit else ""
    rows = conn.execute(
        f"SELECT id, published, description, cvss_score, severity, cwe "
        f"FROM cves {clause} ORDER BY published DESC {limit_clause}",
        params,
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_cve_by_id(cve_id: str):
    conn = get_connection()
    row = conn.execute("SELECT * FROM cves WHERE id = ?", (cve_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_cve_stats():
    conn = get_connection()
    rows = conn.execute("SELECT severity, COUNT(*) FROM cves GROUP BY severity").fetchall()
    conn.close()
    return {row[0] or "UNKNOWN": row[1] for row in rows}


def get_daily_counts():
    conn = get_connection()
    rows = conn.execute(
        "SELECT substr(published, 1, 10) AS day, COUNT(*) AS cnt "
        "FROM cves GROUP BY day ORDER BY day"
    ).fetchall()
    conn.close()
    return [(r[0], r[1]) for r in rows]


def get_recent_critical_count(hours: int = 24) -> int:
    from datetime import datetime, timedelta, timezone
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
    conn = get_connection()
    count = conn.execute(
        "SELECT COUNT(*) FROM cves WHERE severity = 'CRITICAL' AND published >= ?", (cutoff,)
    ).fetchone()[0]
    conn.close()
    return count




def insert_news(record: dict):
    conn = get_connection()
    conn.execute(
        "INSERT OR IGNORE INTO news (title, link, published, source, summary) VALUES (?, ?, ?, ?, ?)",
        (record["title"], record["link"], record["published"],
         record["source"], record.get("summary", "")),
    )
    conn.commit()
    conn.close()


def get_news(limit: int = 20, source: str = None):
    conn = get_connection()
    if source:
        rows = conn.execute(
            "SELECT id, title, link, published, source, summary FROM news "
            "WHERE source = ? ORDER BY published DESC LIMIT ?", (source, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, title, link, published, source, summary FROM news "
            "ORDER BY published DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]




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


def get_exploits(limit: int = 50, exploit_type: str = None):
    conn = get_connection()
    if exploit_type:
        rows = conn.execute(
            "SELECT id, title, link, published, cve_id, platform, exploit_type "
            "FROM exploits WHERE exploit_type = ? ORDER BY published DESC LIMIT ?",
            (exploit_type, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, title, link, published, cve_id, platform, exploit_type "
            "FROM exploits ORDER BY published DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_exploit_by_id(exploit_id: int):
    conn = get_connection()
    row = conn.execute("SELECT * FROM exploits WHERE id = ?", (exploit_id,)).fetchone()
    conn.close()
    return dict(row) if row else None




def create_user(username: str, email: str, password_hash: str, role_id: int = 3):
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, email, password_hash, role_id) VALUES (?, ?, ?, ?)",
            (username, email, password_hash, role_id),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_user_by_username(username: str):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id: int):
    conn = get_connection()
    row = conn.execute(
        "SELECT u.*, r.name as role_name FROM users u JOIN roles r ON u.role_id = r.id WHERE u.id = ?",
        (user_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_users():
    conn = get_connection()
    rows = conn.execute(
        "SELECT u.id, u.username, u.email, r.name as role_name, u.is_active, u.created_at, u.last_login "
        "FROM users u JOIN roles r ON u.role_id = r.id ORDER BY u.created_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_user_last_login(user_id: int):
    conn = get_connection()
    conn.execute("UPDATE users SET last_login = datetime('now') WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def update_user_role(user_id: int, role_id: int):
    conn = get_connection()
    conn.execute("UPDATE users SET role_id = ? WHERE id = ?", (role_id, user_id))
    conn.commit()
    conn.close()


def toggle_user_active(user_id: int):
    conn = get_connection()
    conn.execute("UPDATE users SET is_active = NOT is_active WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def create_session(token: str, user_id: int, hours: int = 24):
    from datetime import datetime, timedelta
    expires = (datetime.utcnow() + timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    conn.execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
        (token, user_id, expires),
    )
    conn.commit()
    conn.close()


def get_session(token: str):
    conn = get_connection()
    row = conn.execute(
        "SELECT s.*, u.username, u.role_id, u.is_active FROM sessions s "
        "JOIN users u ON s.user_id = u.id "
        "WHERE s.token = ? AND s.expires_at > datetime('now')",
        (token,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def delete_session(token: str):
    conn = get_connection()
    conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()




def log_alert(level: str, message: str):
    conn = get_connection()
    conn.execute("INSERT INTO alert_log (level, message) VALUES (?, ?)", (level, message))
    conn.commit()
    conn.close()


def get_alert_log(limit: int = 50):
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, level, message, created_at, is_read FROM alert_log ORDER BY created_at DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def mark_alerts_read():
    conn = get_connection()
    conn.execute("UPDATE alert_log SET is_read = 1 WHERE is_read = 0")
    conn.commit()
    conn.close()




def create_report(data: dict) -> int:
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO reports (title, created_by, date_from, date_to, total_cves, critical, high, medium, low, notes) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (data["title"], data.get("created_by"), data.get("date_from"), data.get("date_to"),
         data.get("total_cves", 0), data.get("critical", 0), data.get("high", 0),
         data.get("medium", 0), data.get("low", 0), data.get("notes", "")),
    )
    conn.commit()
    report_id = cur.lastrowid
    conn.close()
    return report_id


def get_reports(limit: int = 20):
    conn = get_connection()
    rows = conn.execute(
        "SELECT r.*, u.username as author FROM reports r "
        "LEFT JOIN users u ON r.created_by = u.id ORDER BY r.created_at DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_report_by_id(report_id: int):
    conn = get_connection()
    row = conn.execute(
        "SELECT r.*, u.username as author FROM reports r "
        "LEFT JOIN users u ON r.created_by = u.id WHERE r.id = ?",
        (report_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None




def add_to_watchlist(user_id: int, cve_id: str, notes: str = ""):
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO watchlist (user_id, cve_id, notes) VALUES (?, ?, ?)",
            (user_id, cve_id, notes)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def remove_from_watchlist(user_id: int, cve_id: str):
    conn = get_connection()
    conn.execute("DELETE FROM watchlist WHERE user_id = ? AND cve_id = ?", (user_id, cve_id))
    conn.commit()
    conn.close()


def get_watchlist(user_id: int):
    conn = get_connection()
    rows = conn.execute(
        "SELECT w.cve_id, w.added_at, w.notes, c.cvss_score, c.severity, c.description "
        "FROM watchlist w LEFT JOIN cves c ON w.cve_id = c.id "
        "WHERE w.user_id = ? ORDER BY w.added_at DESC",
        (user_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]




def get_tags():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM tags ORDER BY name").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_tag_to_cve(cve_id: str, tag_id: int):
    conn = get_connection()
    try:
        conn.execute("INSERT INTO cve_tags (cve_id, tag_id) VALUES (?, ?)", (cve_id, tag_id))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()


def get_cve_tags(cve_id: str):
    conn = get_connection()
    rows = conn.execute(
        "SELECT t.* FROM tags t JOIN cve_tags ct ON t.id = ct.tag_id WHERE ct.cve_id = ?",
        (cve_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]




def get_total_counts():
    conn = get_connection()
    cve_count     = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    news_count    = conn.execute("SELECT COUNT(*) FROM news").fetchone()[0]
    exploit_count = conn.execute("SELECT COUNT(*) FROM exploits").fetchone()[0]
    conn.close()
    return cve_count, news_count, exploit_count
