import threading
import time
from datetime import datetime
from typing import Callable


class Task:
    def __init__(self, name: str, func: Callable, interval_seconds: int):
        self.name             = name
        self.func             = func
        self.interval_seconds = interval_seconds
        self.last_run: datetime | None = None
        self.run_count        = 0
        self.error_count      = 0
        self.last_error: str | None = None

    def is_due(self) -> bool:
        if self.last_run is None:
            return True
        elapsed = (datetime.utcnow() - self.last_run).total_seconds()
        return elapsed >= self.interval_seconds

    def run(self):
        try:
            self.func()
            self.last_run  = datetime.utcnow()
            self.run_count += 1
            print(f"[Scheduler] {self.name}: выполнено в {self.last_run.strftime('%H:%M:%S')}")
        except Exception as exc:
            self.error_count += 1
            self.last_error   = str(exc)
            print(f"[Scheduler] {self.name}: ошибка — {exc}")

    def to_dict(self) -> dict:
        return {
            "name":     self.name,
            "interval": self.interval_seconds,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "run_count":   self.run_count,
            "error_count": self.error_count,
            "last_error":  self.last_error,
            "next_run":    self._next_run_str(),
        }

    def _next_run_str(self) -> str | None:
        if self.last_run is None:
            return "сейчас"
        from datetime import timedelta
        nxt = self.last_run + timedelta(seconds=self.interval_seconds)
        remaining = (nxt - datetime.utcnow()).total_seconds()
        if remaining <= 0:
            return "сейчас"
        h, rem = divmod(int(remaining), 3600)
        m, s   = divmod(rem, 60)
        return f"через {h:02d}:{m:02d}:{s:02d}"


class Scheduler:
    def __init__(self):
        self._tasks: list[Task] = []
        self._running = False
        self._thread: threading.Thread | None = None

    def add_task(self, name: str, func: Callable, interval_seconds: int) -> "Scheduler":
        self._tasks.append(Task(name, func, interval_seconds))
        return self

    def _loop(self):
        while self._running:
            for task in self._tasks:
                if task.is_due():
                    task.run()
            time.sleep(60)

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        print(f"[Scheduler] Запущен с {len(self._tasks)} задачами")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        print("[Scheduler] Остановлен")

    def get_status(self) -> list[dict]:
        return [t.to_dict() for t in self._tasks]

    def run_now(self, name: str) -> bool:
        for task in self._tasks:
            if task.name == name:
                task.run()
                return True
        return False


def build_default_scheduler() -> Scheduler:
    from src.collectors.nvd_collector import fetch_cves
    from src.collectors.rss_collector import fetch_news
    from src.collectors.exploit_collector import fetch_exploits
    from src.models.alerter import get_alerts
    from src.database.db import log_alert

    def collect_cves():
        fetch_cves(days_back=1, max_results=500)

    def collect_news():
        fetch_news()

    def collect_exploits():
        fetch_exploits()

    def check_alerts():
        alerts = get_alerts()
        for a in alerts:
            if a["level"] in ("critical", "high"):
                log_alert(a["level"], a["message"])

    scheduler = Scheduler()
    scheduler.add_task("Сбор CVE (NVD)",      collect_cves,     interval_seconds=3600)
    scheduler.add_task("Сбор новостей (RSS)",  collect_news,     interval_seconds=1800)
    scheduler.add_task("Сбор эксплойтов",      collect_exploits, interval_seconds=3600)
    scheduler.add_task("Проверка алертов",     check_alerts,     interval_seconds=900)
    return scheduler


_scheduler: Scheduler | None = None


def get_scheduler() -> Scheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = build_default_scheduler()
    return _scheduler
