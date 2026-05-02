from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from src.database.db import get_cves

MODEL_PATH = Path(__file__).parent.parent.parent / "data" / "classifier.pkl"

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
LABEL_MAP = {s: i for i, s in enumerate(SEVERITY_ORDER)}
LABEL_INV = {i: s for s, i in LABEL_MAP.items()}


def _build_dataset():
    rows = get_cves()
    if not rows:
        return None, None

    df = pd.DataFrame(rows, columns=["id", "published", "description", "cvss_score", "severity", "cwe"])
    df = df[df["severity"].isin(LABEL_MAP)].copy()
    df = df[df["description"].notna() & (df["description"].str.len() > 10)].copy()

    if len(df) < 50:
        return None, None

    df["text"] = df["description"] + " " + df["cwe"].fillna("")
    df["label"] = df["severity"].map(LABEL_MAP)
    return df["text"].tolist(), df["label"].tolist()


def train() -> Pipeline | None:
    X, y = _build_dataset()
    if X is None:
        print("[Классификатор] Недостаточно данных для обучения (< 50 записей)")
        return None

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=5000, ngram_range=(1, 2), sublinear_tf=True)),
        ("clf", RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)),
    ])
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    print("[Классификатор] Отчёт по тестовой выборке:")
    print(classification_report(y_test, y_pred, target_names=SEVERITY_ORDER, zero_division=0))

    MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    print(f"[Классификатор] Модель сохранена: {MODEL_PATH}")
    return pipeline


def _load() -> Pipeline | None:
    if MODEL_PATH.exists():
        return joblib.load(MODEL_PATH)
    return train()


def predict(text: str) -> str:
    model = _load()
    if model is None:
        return "UNKNOWN"
    label_idx = model.predict([text])[0]
    return LABEL_INV.get(label_idx, "UNKNOWN")


def get_severity_distribution() -> dict:
    _, y = _build_dataset()
    if y is None:
        return {}
    from collections import Counter
    return {LABEL_INV[k]: v for k, v in Counter(y).items()}


def get_top_features(n: int = 20) -> list[tuple[str, float]]:
    model = _load()
    if model is None:
        return []
    tfidf: TfidfVectorizer = model.named_steps["tfidf"]
    clf: RandomForestClassifier = model.named_steps["clf"]
    feature_names = tfidf.get_feature_names_out()
    importances = clf.feature_importances_
    top_idx = importances.argsort()[::-1][:n]
    return [(feature_names[i], float(importances[i])) for i in top_idx]
