import requests
from src.database.db import get_connection, init_db

MITRE_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


def _ensure_tables():
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS mitre_techniques (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            tactic      TEXT,
            description TEXT,
            url         TEXT,
            is_subtechnique INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS mitre_cve_map (
            technique_id TEXT NOT NULL,
            cve_id       TEXT NOT NULL,
            PRIMARY KEY (technique_id, cve_id)
        );
    """)
    conn.commit()
    conn.close()


def _parse_technique(obj: dict) -> dict | None:
    ext = obj.get("external_references", [])
    mitre_ref = next((r for r in ext if r.get("source_name") == "mitre-attack"), None)
    if not mitre_ref:
        return None

    tech_id = mitre_ref.get("external_id", "")
    if not tech_id.startswith("T"):
        return None

    tactics = []
    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            tactics.append(phase.get("phase_name", ""))

    desc = obj.get("description", "")
    if len(desc) > 600:
        desc = desc[:600] + "..."

    return {
        "id":             tech_id,
        "name":           obj.get("name", ""),
        "tactic":         ", ".join(tactics),
        "description":    desc,
        "url":            mitre_ref.get("url", ""),
        "is_subtechnique": 1 if "." in tech_id else 0,
    }


def _insert_technique(record: dict):
    conn = get_connection()
    conn.execute(
        "INSERT OR REPLACE INTO mitre_techniques "
        "(id, name, tactic, description, url, is_subtechnique) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (record["id"], record["name"], record["tactic"],
         record["description"], record["url"], record["is_subtechnique"]),
    )
    conn.commit()
    conn.close()


def fetch_mitre_techniques(max_techniques: int = 500) -> list[dict]:
    _ensure_tables()
    try:
        print("[MITRE] Загрузка ATT&CK Enterprise matrix...")
        resp = requests.get(MITRE_ENTERPRISE_URL, timeout=60)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        print(f"[MITRE] Ошибка загрузки: {exc}")
        return []

    techniques = []
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        parsed = _parse_technique(obj)
        if parsed:
            _insert_technique(parsed)
            techniques.append(parsed)
            if len(techniques) >= max_techniques:
                break

    print(f"[MITRE] Загружено {len(techniques)} техник ATT&CK")
    return techniques


def get_techniques(tactic: str = None, limit: int = 100) -> list[dict]:
    _ensure_tables()
    conn = get_connection()
    if tactic:
        rows = conn.execute(
            "SELECT id, name, tactic, description, url, is_subtechnique "
            "FROM mitre_techniques WHERE tactic LIKE ? AND is_subtechnique = 0 LIMIT ?",
            (f"%{tactic}%", limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, name, tactic, description, url, is_subtechnique "
            "FROM mitre_techniques WHERE is_subtechnique = 0 LIMIT ?",
            (limit,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_tactics_summary() -> list[dict]:
    _ensure_tables()
    conn = get_connection()
    rows = conn.execute(
        "SELECT tactic, COUNT(*) as cnt FROM mitre_techniques "
        "WHERE tactic != '' AND is_subtechnique = 0 "
        "GROUP BY tactic ORDER BY cnt DESC"
    ).fetchall()
    conn.close()
    result = []
    for row in rows:
        for tac in row[0].split(", "):
            tac = tac.strip()
            if tac:
                result.append({"tactic": tac, "count": row[1]})
    return result


def get_technique_by_id(tech_id: str) -> dict | None:
    _ensure_tables()
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM mitre_techniques WHERE id = ?", (tech_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def search_techniques(query: str, limit: int = 20) -> list[dict]:
    _ensure_tables()
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, name, tactic, description, url FROM mitre_techniques "
        "WHERE name LIKE ? OR description LIKE ? LIMIT ?",
        (f"%{query}%", f"%{query}%", limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_mitre_stats() -> dict:
    _ensure_tables()
    conn = get_connection()
    total      = conn.execute("SELECT COUNT(*) FROM mitre_techniques WHERE is_subtechnique=0").fetchone()[0]
    subtechs   = conn.execute("SELECT COUNT(*) FROM mitre_techniques WHERE is_subtechnique=1").fetchone()[0]
    tactic_cnt = conn.execute("SELECT COUNT(DISTINCT tactic) FROM mitre_techniques").fetchone()[0]
    conn.close()
    return {
        "total_techniques":    total,
        "total_subtechniques": subtechs,
        "total_tactics":       tactic_cnt,
    }
