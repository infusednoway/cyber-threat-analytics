import feedparser

from src.database.db import insert_news

RSS_FEEDS = [
    ("https://feeds.feedburner.com/TheHackersNews", "The Hacker News"),
    ("https://www.bleepingcomputer.com/feed/", "BleepingComputer"),
    ("https://krebsonsecurity.com/feed/", "Krebs on Security"),
    ("https://www.cisa.gov/uscert/ncas/current-activity.xml", "CISA"),
    ("https://securelist.com/feed/", "Kaspersky Securelist"),
]


def _get_published(entry) -> str:
    for attr in ("published", "updated", "created"):
        value = getattr(entry, attr, None)
        if value:
            return value
    return ""


def fetch_news(max_per_feed: int = 20) -> list:
    all_news = []
    for url, source in RSS_FEEDS:
        try:
            feed = feedparser.parse(url)
            count = 0
            for entry in feed.entries[:max_per_feed]:
                record = {
                    "title": entry.get("title", "").strip(),
                    "link": entry.get("link", ""),
                    "published": _get_published(entry),
                    "source": source,
                    "summary": entry.get("summary", "")[:400],
                }
                if record["link"]:
                    insert_news(record)
                    all_news.append(record)
                    count += 1
            print(f"[RSS] {source}: загружено {count} новостей")
        except Exception as exc:
            print(f"[RSS] Ошибка при чтении {source}: {exc}")
    return all_news
