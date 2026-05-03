from __future__ import annotations

import os
import json
import smtplib
import logging
import threading
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from typing               import Optional

import requests

from src.database.db import log_alert, get_connection

logger = logging.getLogger(__name__)


SMTP_HOST    = os.getenv("SMTP_HOST",    "")
SMTP_PORT    = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER    = os.getenv("SMTP_USER",    "")
SMTP_PASS    = os.getenv("SMTP_PASS",    "")
SMTP_FROM    = os.getenv("SMTP_FROM",    SMTP_USER)
WEBHOOK_URL  = os.getenv("WEBHOOK_URL",  "")

_THREAD_LOCK = threading.Lock()


_SLACK_COLOR = {
    "CRITICAL": "#f85149",
    "HIGH":     "#e3b341",
    "MEDIUM":   "#3fb950",
    "LOW":      "#58a6ff",
    "INFO":     "#8b949e",
}


def notify_inapp(level: str, message: str, context: str = "") -> int:
    full_msg = f"{message}. {context}".strip(" .")
    log_alert(level, full_msg)
    logger.info("[notify:inapp] %s — %s", level, message)
    return 1


def _build_html_email(subject: str, level: str, body: str) -> str:
    color = {"CRITICAL": "#f85149", "HIGH": "#e3b341",
             "MEDIUM":   "#3fb950", "INFO": "#8b949e"}.get(level.upper(), "#c9d1d9")
    return f"""
    <html><body style="font-family:Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px;">
      <div style="max-width:600px;margin:auto;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:24px;">
        <h2 style="color:{color};margin-top:0;">[{level}] {subject}</h2>
        <pre style="white-space:pre-wrap;font-size:13px;color:#c9d1d9;">{body}</pre>
        <hr style="border-color:#30363d;"/>
        <small style="color:#8b949e;">CyberThreat Analytics • {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</small>
      </div>
    </body></html>"""


def send_email(to_addresses: list[str], subject: str,
               body: str, level: str = "INFO") -> bool:
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS):
        logger.debug("E-mail not configured (SMTP_HOST/USER/PASS missing)")
        return False
    if not to_addresses:
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[CTA] {subject}"
    msg["From"]    = SMTP_FROM
    msg["To"]      = ", ".join(to_addresses)
    msg.attach(MIMEText(body, "plain"))
    msg.attach(MIMEText(_build_html_email(subject, level, body), "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, to_addresses, msg.as_string())
        logger.info("[notify:email] sent '%s' to %s", subject, to_addresses)
        return True
    except smtplib.SMTPException as exc:
        logger.error("[notify:email] SMTP error: %s", exc)
        return False
    except Exception as exc:
        logger.error("[notify:email] unexpected error: %s", exc)
        return False


def _build_slack_payload(title: str, body: str, level: str) -> dict:
    color = _SLACK_COLOR.get(level.upper(), "#8b949e")
    return {
        "attachments": [{
            "color":  color,
            "title":  f"[{level}] {title}",
            "text":   body[:2000],
            "footer": "CyberThreat Analytics",
            "ts":     int(datetime.utcnow().timestamp()),
        }]
    }


def send_webhook(url: str, title: str, body: str,
                 level: str = "INFO", timeout: int = 10) -> bool:
    target = url or WEBHOOK_URL
    if not target:
        logger.debug("Webhook not configured (WEBHOOK_URL missing)")
        return False
    payload = _build_slack_payload(title, body, level)
    try:
        r = requests.post(target, json=payload, timeout=timeout)
        r.raise_for_status()
        logger.info("[notify:webhook] sent '%s'", title)
        return True
    except Exception as exc:
        logger.error("[notify:webhook] error: %s", exc)
        return False


def send_raw_webhook(url: str, data: dict, timeout: int = 10) -> bool:
    if not url:
        return False
    try:
        r = requests.post(url, json=data, timeout=timeout)
        r.raise_for_status()
        return True
    except Exception as exc:
        logger.error("[notify:webhook:raw] error: %s", exc)
        return False


def dispatch(level: str, title: str, body: str,
             email_to: Optional[list[str]] = None,
             webhook_url: str = "") -> dict[str, bool]:
    results: dict[str, bool] = {}

    def _inapp():
        results["inapp"] = bool(notify_inapp(level, title, body))

    def _email():
        if email_to:
            results["email"] = send_email(email_to, title, body, level)

    def _hook():
        if webhook_url or WEBHOOK_URL:
            results["webhook"] = send_webhook(webhook_url, title, body, level)

    threads = [
        threading.Thread(target=_inapp, daemon=True),
        threading.Thread(target=_email, daemon=True),
        threading.Thread(target=_hook,  daemon=True),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    return results


def notify_new_critical_cve(cve_id: str, cvss: float,
                             description: str = "",
                             email_to: Optional[list[str]] = None) -> dict:
    title = f"Critical CVE detected: {cve_id} (CVSS {cvss})"
    body  = f"CVE ID: {cve_id}\nCVSS Score: {cvss}\n\n{description[:500]}"
    return dispatch("CRITICAL", title, body, email_to=email_to)


def notify_exploit_published(cve_id: str, exploit_title: str,
                              source: str = "",
                              email_to: Optional[list[str]] = None) -> dict:
    title = f"Public exploit published for {cve_id}"
    body  = f"Exploit: {exploit_title}\nSource: {source}\nCVE: {cve_id}"
    return dispatch("HIGH", title, body, email_to=email_to)


def notify_anomaly_detected(date: str, count: int, zscore: float,
                             email_to: Optional[list[str]] = None) -> dict:
    title = f"Anomaly detected on {date}: {count} CVEs (z={zscore:.2f})"
    body  = (f"Date: {date}\nCVE count: {count}\n"
             f"Z-score: {zscore:.2f}\n"
             f"This is significantly above the rolling average.")
    return dispatch("HIGH", title, body, email_to=email_to)


def notify_weekly_digest(summary: dict,
                         email_to: Optional[list[str]] = None) -> dict:
    totals = summary.get("totals", {})
    growth = summary.get("weekly_growth_pct", 0)
    risk   = summary.get("risk_level", "UNKNOWN")
    title  = f"Weekly digest — risk level: {risk}"
    body   = (
        f"Period: {summary.get('period', {})}\n"
        f"CVEs:    {totals.get('cves', 0)}\n"
        f"Exploits:{totals.get('exploits', 0)}\n"
        f"News:    {totals.get('news', 0)}\n"
        f"Growth:  {growth}%\n"
        f"Risk:    {risk}"
    )
    return dispatch("INFO", title, body, email_to=email_to)


def get_notification_subscribers() -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, username, email FROM users WHERE is_active = 1 AND email IS NOT NULL"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_admin_emails() -> list[str]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT email FROM users WHERE role_id = 1 AND is_active = 1 AND email IS NOT NULL"
    ).fetchall()
    conn.close()
    return [r["email"] for r in rows if r["email"]]


def get_analyst_emails() -> list[str]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT email FROM users WHERE role_id IN (1,2) AND is_active = 1 AND email IS NOT NULL"
    ).fetchall()
    conn.close()
    return [r["email"] for r in rows if r["email"]]


def get_notification_history(limit: int = 50) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, level, message, created_at FROM alert_log "
        "ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_unread_count() -> int:
    conn = get_connection()
    row  = conn.execute(
        "SELECT COUNT(*) as cnt FROM alert_log WHERE is_read = 0"
    ).fetchone()
    conn.close()
    return row["cnt"] if row else 0


def mark_all_read() -> None:
    conn = get_connection()
    conn.execute("UPDATE alert_log SET is_read = 1")
    conn.commit()
    conn.close()


def check_channels() -> dict[str, dict]:
    return {
        "inapp": {
            "enabled": True,
            "status":  "ok",
        },
        "email": {
            "enabled": bool(SMTP_HOST and SMTP_USER),
            "status":  "configured" if (SMTP_HOST and SMTP_USER) else "not configured",
            "host":    SMTP_HOST or "—",
            "port":    SMTP_PORT,
        },
        "webhook": {
            "enabled": bool(WEBHOOK_URL),
            "status":  "configured" if WEBHOOK_URL else "not configured",
            "url":     WEBHOOK_URL[:30] + "…" if len(WEBHOOK_URL) > 30 else WEBHOOK_URL,
        },
    }
