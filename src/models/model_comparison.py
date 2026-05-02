from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier

from src.database.db import get_cves

RESULTS_PATH = Path(__file__).parent.parent.parent / "data" / "model_comparison.json"

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
LABEL_MAP = {s: i for i, s in enumerate(SEVERITY_ORDER)}

MODELS = {
    "Логистическая регрессия": LogisticRegression(max_iter=1000, random_state=42),
    "Случайный лес":           RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
    "Метод опорных векторов":  LinearSVC(max_iter=2000, random_state=42),
}


def _build_dataset():
    rows = get_cves()
    if not rows:
        return None, None

    df = pd.DataFrame(rows, columns=["id", "published", "description", "cvss_score", "severity", "cwe"])
    df = df[df["severity"].isin(LABEL_MAP)].copy()
    df = df[df["description"].notna() & (df["description"].str.len() > 10)].copy()

    if len(df) < 50:
        return None, None

    df["text"]  = df["description"] + " " + df["cwe"].fillna("")
    df["label"] = df["severity"].map(LABEL_MAP)
    return df["text"].tolist(), df["label"].tolist()


def run_comparison() -> list[dict]:
    X, y = _build_dataset()
    if X is None:
        print("[Сравнение] Недостаточно данных (< 50 записей)")
        return []

    tfidf = TfidfVectorizer(max_features=5000, ngram_range=(1, 2), sublinear_tf=True)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    results = []
    for name, clf in MODELS.items():
        pipeline = Pipeline([("tfidf", tfidf), ("clf", clf)])
        scores = cross_validate(
            pipeline, X, y, cv=cv,
            scoring=["accuracy", "f1_weighted", "precision_weighted", "recall_weighted"],
            n_jobs=-1,
        )
        row = {
            "model":     name,
            "accuracy":  round(float(scores["test_accuracy"].mean()), 4),
            "f1":        round(float(scores["test_f1_weighted"].mean()), 4),
            "precision": round(float(scores["test_precision_weighted"].mean()), 4),
            "recall":    round(float(scores["test_recall_weighted"].mean()), 4),
        }
        results.append(row)
        print(f"  {name}: точность={row['accuracy']:.3f}  F1={row['f1']:.3f}")

    results.sort(key=lambda r: r["f1"], reverse=True)

    import json
    RESULTS_PATH.parent.mkdir(exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[Сравнение] Результаты сохранены: {RESULTS_PATH}")
    return results


def load_comparison() -> list[dict]:
    import json
    if RESULTS_PATH.exists():
        return json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
    return run_comparison()
