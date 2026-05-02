import csv
import io
from flask import Blueprint, jsonify, request, Response

from src.auth.auth import login_required, get_current_user
from src.database.db import get_cves, get_exploits, get_news, get_total_counts
from src.models.alerter import get_alerts
from src.models.classifier import get_top_features
from src.models.model_comparison import load_comparison
from src.models.predictor import (
    get_severity_distribution, get_timeline_data,
    get_weekly_growth, predict_next_days,
)

api_bp = Blueprint("api_bp", __name__, url_prefix="/api")


@api_bp.route("/summary")
@login_required
def api_summary():
    cve_total, news_total, exploit_total = get_total_counts()
    severity = get_severity_distribution()
    return jsonify({
        "cve_total":      cve_total,
        "news_total":     news_total,
        "exploit_total":  exploit_total,
        "weekly_growth":  get_weekly_growth(),
        "critical_count": severity.get("CRITICAL", 0),
        "high_count":     severity.get("HIGH", 0),
        "severity":       severity,
    })


@api_bp.route("/timeline")
@login_required
def api_timeline():
    data        = get_timeline_data()
    predictions = predict_next_days(14)
    data["pred_dates"]  = [p["date"] for p in predictions]
    data["pred_counts"] = [p["predicted_count"] for p in predictions]
    return jsonify(data)


@api_bp.route("/alerts")
@login_required
def api_alerts():
    return jsonify(get_alerts())


@api_bp.route("/cves")
@login_required
def api_cves():
    severity = request.args.get("severity")
    search   = request.args.get("search")
    rows = get_cves(limit=100, severity=severity, search=search)
    return jsonify(rows)


@api_bp.route("/exploits")
@login_required
def api_exploits():
    exploit_type = request.args.get("type")
    rows = get_exploits(limit=50, exploit_type=exploit_type)
    return jsonify(rows)


@api_bp.route("/news")
@login_required
def api_news():
    source = request.args.get("source")
    return jsonify(get_news(limit=30, source=source))


@api_bp.route("/features")
@login_required
def api_features():
    features = get_top_features(15)
    return jsonify([{"term": t, "importance": imp} for t, imp in features])


@api_bp.route("/model_comparison")
@login_required
def api_model_comparison():
    return jsonify(load_comparison())


@api_bp.route("/export/cves")
@login_required
def export_cves():
    rows = get_cves(limit=5000)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["id", "published", "description", "cvss_score", "severity", "cwe"])
    writer.writeheader()
    writer.writerows(rows)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=cves_export.csv"},
    )


@api_bp.route("/export/exploits")
@login_required
def export_exploits():
    rows = get_exploits(limit=5000)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["id", "title", "link", "published", "cve_id", "platform", "exploit_type"])
    writer.writeheader()
    writer.writerows(rows)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=exploits_export.csv"},
    )
