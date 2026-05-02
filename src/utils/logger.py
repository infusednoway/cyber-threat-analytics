import logging
import sys
from datetime import datetime
from pathlib import Path

LOG_DIR  = Path(__file__).parent.parent.parent / "data" / "logs"
LOG_FILE = LOG_DIR / "app.log"

_COLORS = {
    "DEBUG":    "\033[36m",
    "INFO":     "\033[32m",
    "WARNING":  "\033[33m",
    "ERROR":    "\033[31m",
    "CRITICAL": "\033[35m",
    "RESET":    "\033[0m",
}


class ColorFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        color = _COLORS.get(record.levelname, "")
        reset = _COLORS["RESET"]
        ts    = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        return f"{color}[{ts}] [{record.levelname:<8}] {record.name}: {record.getMessage()}{reset}"


class PlainFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        return f"[{ts}] [{record.levelname}] {record.name}: {record.getMessage()}"


def setup_logger(name: str = "cyber_threat", level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(level)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(ColorFormatter())
    logger.addHandler(console)

    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
        file_handler.setFormatter(PlainFormatter())
        logger.addHandler(file_handler)
    except OSError:
        pass

    return logger


_logger = setup_logger()


def get_logger(name: str = None) -> logging.Logger:
    if name:
        return logging.getLogger(f"cyber_threat.{name}")
    return _logger


def log_collection_event(source: str, count: int, success: bool = True):
    msg = f"Сбор из {source}: {'успешно' if success else 'ошибка'}, записей: {count}"
    if success:
        _logger.info(msg)
    else:
        _logger.error(msg)


def log_auth_event(username: str, action: str, ip: str = "unknown"):
    _logger.info(f"AUTH | {action} | user={username} | ip={ip}")


def log_alert_triggered(level: str, message: str):
    if level in ("critical", "high"):
        _logger.warning(f"ALERT [{level.upper()}]: {message}")
    else:
        _logger.info(f"ALERT [{level.upper()}]: {message}")


def log_model_event(model_name: str, accuracy: float, event: str = "trained"):
    _logger.info(f"MODEL | {event} | {model_name} | accuracy={accuracy:.4f}")


def get_recent_logs(n: int = 100) -> list[str]:
    if not LOG_FILE.exists():
        return []
    try:
        lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
        return lines[-n:] if len(lines) > n else lines
    except OSError:
        return []


def clear_logs():
    if LOG_FILE.exists():
        LOG_FILE.write_text("", encoding="utf-8")
