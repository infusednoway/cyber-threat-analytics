from src.database.db import get_recent_critical_count, get_exploits
from src.models.predictor import get_weekly_growth

THRESHOLDS = {
    "critical_24h": 5,
    "weekly_growth": 25.0,
    "new_exploits_24h": 3,
}

LEVELS = {
    "critical": {"color": "#f85149", "label": "КРИТИЧЕСКИЙ"},
    "high":     {"color": "#e3b341", "label": "ВЫСОКИЙ"},
    "medium":   {"color": "#3fb950", "label": "СРЕДНИЙ"},
    "info":     {"color": "#58a6ff", "label": "ИНФОРМАЦИЯ"},
}


def _count_recent_exploits(hours: int = 24) -> int:
    from datetime import datetime, timedelta
    import email.utils

    cutoff = datetime.utcnow() - timedelta(hours=hours)
    count = 0
    for row in get_exploits(limit=200):
        published_str = row.get("published") if hasattr(row, "get") else row[3]
        if not published_str:
            continue
        try:
            dt = datetime(*email.utils.parsedate(published_str)[:6])
            if dt >= cutoff:
                count += 1
        except Exception:
            pass
    return count


def get_alerts() -> list[dict]:
    alerts = []

    critical_24h = get_recent_critical_count(hours=24)
    if critical_24h >= THRESHOLDS["critical_24h"]:
        alerts.append({
            "level": "critical",
            "color": LEVELS["critical"]["color"],
            "label": LEVELS["critical"]["label"],
            "message": (
                f"За последние 24 часа обнаружено {critical_24h} критических уязвимостей. "
                "Рекомендуется незамедлительная проверка затронутых систем."
            ),
        })

    growth = get_weekly_growth()
    if growth >= THRESHOLDS["weekly_growth"]:
        alerts.append({
            "level": "high",
            "color": LEVELS["high"]["color"],
            "label": LEVELS["high"]["label"],
            "message": (
                f"Недельный прирост числа CVE составил +{growth}%. "
                "Наблюдается аномальный рост активности угроз."
            ),
        })
    elif growth > 0:
        alerts.append({
            "level": "medium",
            "color": LEVELS["medium"]["color"],
            "label": LEVELS["medium"]["label"],
            "message": f"Число CVE за неделю выросло на {growth}%. Рекомендуется мониторинг.",
        })

    new_exploits = _count_recent_exploits(hours=24)
    if new_exploits >= THRESHOLDS["new_exploits_24h"]:
        alerts.append({
            "level": "high",
            "color": LEVELS["high"]["color"],
            "label": LEVELS["high"]["label"],
            "message": (
                f"За последние 24 часа опубликовано {new_exploits} новых публичных эксплойтов. "
                "Высокий риск эксплуатации уязвимостей."
            ),
        })

    if not alerts:
        alerts.append({
            "level": "info",
            "color": LEVELS["info"]["color"],
            "label": LEVELS["info"]["label"],
            "message": "Критических угроз не обнаружено. Система работает в штатном режиме.",
        })

    return alerts
