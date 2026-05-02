import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from src.database.db import get_daily_counts, get_cve_stats


class AnomalyDetector:
    def __init__(self, window: int = 7, threshold_sigma: float = 2.0):
        self.window          = window
        self.threshold_sigma = threshold_sigma
        self._series: pd.Series | None = None

    def fit(self, series: pd.Series):
        self._series = series.copy()

    def detect(self) -> list[dict]:
        if self._series is None or len(self._series) < self.window + 1:
            return []

        anomalies = []
        values    = self._series.values.astype(float)
        dates     = self._series.index.tolist()

        for i in range(self.window, len(values)):
            window_data = values[i - self.window: i]
            mu    = window_data.mean()
            sigma = window_data.std()

            if sigma == 0:
                continue

            z_score = (values[i] - mu) / sigma

            if abs(z_score) >= self.threshold_sigma:
                direction = "рост" if z_score > 0 else "спад"
                anomalies.append({
                    "date":    str(dates[i]),
                    "value":   int(values[i]),
                    "z_score": round(float(z_score), 2),
                    "mean":    round(float(mu), 1),
                    "std":     round(float(sigma), 1),
                    "direction": direction,
                    "severity": "high" if abs(z_score) >= 3.0 else "medium",
                })

        return anomalies

    def get_bounds(self) -> dict:
        if self._series is None or len(self._series) < self.window:
            return {}

        values = self._series.values.astype(float)
        window_data = values[-self.window:]
        mu    = window_data.mean()
        sigma = window_data.std()

        return {
            "mean":       round(float(mu), 1),
            "std":        round(float(sigma), 1),
            "upper_bound": round(float(mu + self.threshold_sigma * sigma), 1),
            "lower_bound": max(0.0, round(float(mu - self.threshold_sigma * sigma), 1)),
        }


def _load_series() -> pd.Series:
    rows = get_daily_counts()
    if not rows:
        return pd.Series(dtype=float)
    df = pd.DataFrame(rows, columns=["date", "count"])
    df["date"] = pd.to_datetime(df["date"])
    df = df.sort_values("date").set_index("date")
    return df["count"].astype(float)


def detect_anomalies(window: int = 7, sigma: float = 2.0) -> list[dict]:
    series   = _load_series()
    detector = AnomalyDetector(window=window, threshold_sigma=sigma)
    detector.fit(series)
    return detector.detect()


def get_anomaly_bounds(window: int = 7, sigma: float = 2.0) -> dict:
    series   = _load_series()
    detector = AnomalyDetector(window=window, threshold_sigma=sigma)
    detector.fit(series)
    return detector.get_bounds()


def get_anomaly_summary() -> dict:
    anomalies = detect_anomalies()
    bounds    = get_anomaly_bounds()
    if not anomalies:
        return {"total": 0, "high": 0, "medium": 0, "bounds": bounds, "latest": None}

    high   = sum(1 for a in anomalies if a["severity"] == "high")
    medium = sum(1 for a in anomalies if a["severity"] == "medium")
    latest = anomalies[-1]

    return {
        "total":   len(anomalies),
        "high":    high,
        "medium":  medium,
        "bounds":  bounds,
        "latest":  latest,
        "list":    anomalies,
    }


def get_rolling_stats(window: int = 7) -> list[dict]:
    series = _load_series()
    if len(series) < window:
        return []

    rolling_mean = series.rolling(window=window, min_periods=1).mean()
    rolling_std  = series.rolling(window=window, min_periods=1).std().fillna(0)

    result = []
    for date, value in series.items():
        mu    = rolling_mean[date]
        sigma = rolling_std[date]
        result.append({
            "date":  str(date.date()),
            "value": int(value),
            "mean":  round(float(mu), 1),
            "upper": round(float(mu + 2 * sigma), 1),
            "lower": max(0.0, round(float(mu - 2 * sigma), 1)),
        })
    return result
