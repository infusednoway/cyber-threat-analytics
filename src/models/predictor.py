import numpy as np
import pandas as pd
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import PolynomialFeatures
from sklearn.pipeline import make_pipeline

from src.database.db import get_daily_counts, get_cve_stats


def _load_series() -> pd.DataFrame:
    rows = get_daily_counts()
    if not rows:
        return pd.DataFrame(columns=["date", "count"])
    df = pd.DataFrame(rows, columns=["date", "count"])
    df["date"] = pd.to_datetime(df["date"])
    return df.sort_values("date").reset_index(drop=True)


def predict_next_days(days_ahead: int = 14) -> list[dict]:
    df = _load_series()
    if len(df) < 7:
        return []

    df["idx"] = np.arange(len(df))
    X = df["idx"].values.reshape(-1, 1)
    y = df["count"].values.astype(float)

    model = make_pipeline(PolynomialFeatures(degree=2), LinearRegression())
    model.fit(X, y)

    last_idx = int(df["idx"].max())
    future_idx = np.arange(last_idx + 1, last_idx + 1 + days_ahead).reshape(-1, 1)
    preds = np.maximum(model.predict(future_idx), 0).round().astype(int)

    last_date = df["date"].max()
    future_dates = pd.date_range(start=last_date + pd.Timedelta(days=1), periods=days_ahead)

    return [
        {"date": str(d.date()), "predicted_count": int(p)}
        for d, p in zip(future_dates, preds)
    ]


def get_timeline_data() -> dict:
    df = _load_series()
    if df.empty:
        return {"dates": [], "counts": [], "ma7": []}

    counts = df["count"].tolist()
    ma7 = df["count"].rolling(window=7, min_periods=1).mean().round(1).tolist()

    return {
        "dates": df["date"].dt.strftime("%Y-%m-%d").tolist(),
        "counts": counts,
        "ma7": ma7,
    }


def get_weekly_growth() -> float:
    df = _load_series()
    if len(df) < 14:
        return 0.0
    last7 = df["count"].tail(7).sum()
    prev7 = df["count"].tail(14).head(7).sum()
    if prev7 == 0:
        return 0.0
    return round((last7 - prev7) / prev7 * 100, 1)


def get_severity_distribution() -> dict:
    return get_cve_stats()
