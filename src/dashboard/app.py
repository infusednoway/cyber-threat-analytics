from flask import Flask, jsonify, render_template

from src.database.db import get_cves, get_news, get_exploits, get_total_counts
from src.models.alerter import get_alerts
from src.models.classifier import get_top_features
from src.models.model_comparison import load_comparison
from src.models.predictor import (
    get_severity_distribution,
    get_timeline_data,
    get_weekly_growth,
    predict_next_days,
)

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/summary")
def api_summary():
    cve_total, news_total, exploit_total = get_total_counts()
    severity = get_severity_distribution()
    growth   = get_weekly_growth()
    return jsonify({
        "cve_total":     cve_total,
        "news_total":    news_total,
        "exploit_total": exploit_total,
        "weekly_growth": growth,
        "critical_count": severity.get("CRITICAL", 0),
        "high_count":     severity.get("HIGH", 0),
        "severity":       severity,
    })


@app.route("/api/timeline")
def api_timeline():
    data = get_timeline_data()
    predictions = predict_next_days(14)
    data["pred_dates"]  = [p["date"] for p in predictions]
    data["pred_counts"] = [p["predicted_count"] for p in predictions]
    return jsonify(data)


@app.route("/api/alerts")
def api_alerts():
    return jsonify(get_alerts())


@app.route("/api/exploits")
def api_exploits():
    rows = get_exploits(limit=50)
    return jsonify([
        {
            "title":        r[1],
            "link":         r[2],
            "published":    r[3],
            "cve_id":       r[4] or "—",
            "platform":     r[5] or "Unknown",
            "exploit_type": r[6] or "Other",
        }
        for r in rows
    ])


@app.route("/api/cves")
def api_cves():
    rows = get_cves(limit=100)
    return jsonify([
        {
            "id":          r[0],
            "published":   r[1][:10] if r[1] else "",
            "description": (r[2] or "")[:160],
            "cvss_score":  r[3],
            "severity":    r[4] or "UNKNOWN",
            "cwe":         r[5] or "",
        }
        for r in rows
    ])


@app.route("/api/news")
def api_news():
    rows = get_news(limit=30)
    return jsonify([
        {"title": r[1], "link": r[2], "published": r[3], "source": r[4], "summary": r[5]}
        for r in rows
    ])


@app.route("/api/features")
def api_features():
    features = get_top_features(15)
    return jsonify([{"term": t, "importance": imp} for t, imp in features])


@app.route("/api/model_comparison")
def api_model_comparison():
    return jsonify(load_comparison())


def run(host: str = "127.0.0.1", port: int = 5000, debug: bool = False):
    app.run(host=host, port=port, debug=debug)
