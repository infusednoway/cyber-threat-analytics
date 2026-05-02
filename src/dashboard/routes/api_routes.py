import csv
import io
from flask import Blueprint, jsonify, request, Response

from src.auth.auth import login_required, get_current_user
from src.database.db import get_cves, get_exploits, get_news, get_total_counts
from src.models.alerter import get_alerts
from src.models.anomaly import get_anomaly_summary, get_rolling_stats
from src.models.classifier import get_top_features
from src.models.model_comparison import load_comparison
from src.models.predictor import (
    get_severity_distribution, get_timeline_data,
    get_weekly_growth, predict_next_days,
)
from src.utils.statistics import (
    get_top_cwe, get_cvss_distribution, get_exploit_type_stats,
    get_exploit_platform_stats, get_news_source_stats, get_summary_stats,
    get_cves_with_exploits,
)
from src.utils.exporter import (
    export_cves_csv, export_exploits_csv, export_news_csv,
    export_report_json, export_full_snapshot_json,
)
from src.collectors.mitre_collector import (
    get_techniques, get_tactics_summary, search_techniques, get_mitre_stats,
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
    return Response(export_cves_csv(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=cves_export.csv"})


@api_bp.route("/export/exploits")
@login_required
def export_exploits():
    return Response(export_exploits_csv(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=exploits_export.csv"})


@api_bp.route("/export/news")
@login_required
def export_news():
    return Response(export_news_csv(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=news_export.csv"})


@api_bp.route("/export/snapshot")
@login_required
def export_snapshot():
    return Response(export_full_snapshot_json(), mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=snapshot.json"})


@api_bp.route("/export/report/<int:report_id>")
@login_required
def export_report(report_id):
    fmt = request.args.get("format", "json")
    if fmt == "pdf":
        from src.utils.exporter import build_pdf_report
        pdf = build_pdf_report(report_id)
        return Response(pdf, mimetype="application/pdf",
                        headers={"Content-Disposition": f"attachment; filename=report_{report_id}.pdf"})
    return Response(export_report_json(report_id), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=report_{report_id}.json"})


@api_bp.route("/statistics")
@login_required
def api_statistics():
    return jsonify({
        "summary":          get_summary_stats(),
        "top_cwe":          get_top_cwe(10),
        "cvss_distribution": get_cvss_distribution(),
        "exploit_types":    get_exploit_type_stats(),
        "exploit_platforms": get_exploit_platform_stats(),
        "news_sources":     get_news_source_stats(),
        "cves_with_exploits": get_cves_with_exploits(),
    })


@api_bp.route("/anomalies")
@login_required
def api_anomalies():
    window = request.args.get("window", 7, type=int)
    sigma  = request.args.get("sigma",  2.0, type=float)
    return jsonify({
        "summary":      get_anomaly_summary(),
        "rolling_stats": get_rolling_stats(window),
    })


@api_bp.route("/mitre/techniques")
@login_required
def api_mitre_techniques():
    tactic = request.args.get("tactic")
    limit  = request.args.get("limit", 100, type=int)
    return jsonify(get_techniques(tactic=tactic, limit=limit))


@api_bp.route("/mitre/tactics")
@login_required
def api_mitre_tactics():
    return jsonify(get_tactics_summary())


@api_bp.route("/mitre/search")
@login_required
def api_mitre_search():
    q = request.args.get("q", "")
    return jsonify(search_techniques(q))


@api_bp.route("/mitre/stats")
@login_required
def api_mitre_stats():
    return jsonify(get_mitre_stats())


@api_bp.route("/scheduler/status")
@login_required
def api_scheduler_status():
    from src.utils.scheduler import get_scheduler
    return jsonify(get_scheduler().get_status())


# ─────────────── NLP analysis ────────────────────────────────────────────────

@api_bp.route("/nlp/threat_distribution")
@login_required
def api_nlp_threat_distribution():
    from src.models.nlp_analyzer import get_threat_type_distribution
    limit = request.args.get("limit", 1000, type=int)
    return jsonify(get_threat_type_distribution(limit))


@api_bp.route("/nlp/product_exposure")
@login_required
def api_nlp_product_exposure():
    from src.models.nlp_analyzer import get_product_exposure
    limit = request.args.get("limit", 1000, type=int)
    return jsonify(get_product_exposure(limit))


@api_bp.route("/nlp/keywords")
@login_required
def api_nlp_keywords():
    from src.models.nlp_analyzer import get_top_keywords_across_cves
    limit  = request.args.get("limit", 500, type=int)
    top_n  = request.args.get("top_n", 30,  type=int)
    return jsonify(get_top_keywords_across_cves(limit, top_n))


@api_bp.route("/nlp/cve/<cve_id>")
@login_required
def api_nlp_cve(cve_id):
    from src.models.nlp_analyzer import analyze_cve_text
    result = analyze_cve_text(cve_id)
    if not result:
        return jsonify({"error": "CVE not found"}), 404
    return jsonify(result)


@api_bp.route("/nlp/news_sentiment")
@login_required
def api_nlp_news_sentiment():
    from src.models.nlp_analyzer import analyze_news_sentiment
    limit = request.args.get("limit", 100, type=int)
    return jsonify(analyze_news_sentiment(limit))


# ─────────────── risk scoring ────────────────────────────────────────────────

@api_bp.route("/risk/top")
@login_required
def api_risk_top():
    from src.models.risk_scorer import get_top_risk_cves
    n     = request.args.get("n",     20,  type=int)
    limit = request.args.get("limit", 500, type=int)
    return jsonify(get_top_risk_cves(n=n, limit=limit))


@api_bp.route("/risk/distribution")
@login_required
def api_risk_distribution():
    from src.models.risk_scorer import get_risk_distribution
    limit = request.args.get("limit", 1000, type=int)
    return jsonify(get_risk_distribution(limit))


@api_bp.route("/risk/cve/<cve_id>")
@login_required
def api_risk_cve(cve_id):
    from src.models.risk_scorer import get_risk_score_for_cve
    result = get_risk_score_for_cve(cve_id)
    if not result:
        return jsonify({"error": "CVE not found"}), 404
    return jsonify(result)


@api_bp.route("/risk/trend")
@login_required
def api_risk_trend():
    from src.models.risk_scorer import get_risk_trend
    days = request.args.get("days", 30, type=int)
    return jsonify(get_risk_trend(days))


@api_bp.route("/risk/high_with_exploit")
@login_required
def api_risk_high_exploit():
    from src.models.risk_scorer import get_high_risk_with_exploit
    limit = request.args.get("limit", 500, type=int)
    return jsonify(get_high_risk_with_exploit(limit))


@api_bp.route("/risk/explain/<cve_id>")
@login_required
def api_risk_explain(cve_id):
    from src.models.risk_scorer import explain_score
    text = explain_score(cve_id)
    if not text:
        return jsonify({"error": "CVE not found"}), 404
    return jsonify({"cve_id": cve_id, "explanation": text})


# ─────────────── Shodan exposure ─────────────────────────────────────────────

@api_bp.route("/shodan/status")
@login_required
def api_shodan_status():
    from src.collectors.shodan_collector import get_api_status
    return jsonify(get_api_status())


@api_bp.route("/shodan/exposure/<cve_id>")
@login_required
def api_shodan_exposure(cve_id):
    from src.collectors.shodan_collector import enrich_cve_with_exposure
    return jsonify(enrich_cve_with_exposure(cve_id))


@api_bp.route("/shodan/hosts/<cve_id>")
@login_required
def api_shodan_hosts(cve_id):
    from src.collectors.shodan_collector import search_hosts_for_cve
    limit = request.args.get("limit", 20, type=int)
    return jsonify(search_hosts_for_cve(cve_id, limit=limit))


@api_bp.route("/shodan/port_stats")
@login_required
def api_shodan_port_stats():
    from src.collectors.shodan_collector import get_port_stats
    return jsonify(get_port_stats())


# ─────────────── report builder ──────────────────────────────────────────────

@api_bp.route("/report/executive")
@login_required
def api_report_executive():
    from src.utils.report_builder import build_executive_summary
    date_from = request.args.get("from", "")
    date_to   = request.args.get("to",   "")
    return jsonify(build_executive_summary(date_from, date_to))


@api_bp.route("/report/full")
@login_required
def api_report_full():
    from src.utils.report_builder import build_full_report
    date_from = request.args.get("from", "")
    date_to   = request.args.get("to",   "")
    return jsonify(build_full_report(date_from, date_to))


@api_bp.route("/report/weekly")
@login_required
def api_report_weekly():
    from src.utils.report_builder import build_weekly_digest
    return jsonify(build_weekly_digest())


@api_bp.route("/report/severity_heatmap")
@login_required
def api_severity_heatmap():
    from src.utils.report_builder import get_severity_heatmap
    weeks = request.args.get("weeks", 8, type=int)
    return jsonify(get_severity_heatmap(weeks))


@api_bp.route("/report/cvss_percentiles")
@login_required
def api_cvss_percentiles():
    from src.utils.report_builder import get_cvss_percentiles
    bins = request.args.get("bins", 10, type=int)
    return jsonify(get_cvss_percentiles(bins))


@api_bp.route("/report/compare_periods")
@login_required
def api_compare_periods():
    from src.utils.report_builder import compare_periods
    days_a = request.args.get("days_a", 7,  type=int)
    days_b = request.args.get("days_b", 14, type=int)
    return jsonify(compare_periods(days_a, days_b))


# ─────────────── notifications ───────────────────────────────────────────────

@api_bp.route("/notifications/history")
@login_required
def api_notifications_history():
    from src.utils.notifier import get_notification_history
    limit = request.args.get("limit", 50, type=int)
    return jsonify(get_notification_history(limit))


@api_bp.route("/notifications/unread")
@login_required
def api_notifications_unread():
    from src.utils.notifier import get_unread_count
    return jsonify({"unread": get_unread_count()})


@api_bp.route("/notifications/channels")
@login_required
def api_notifications_channels():
    from src.utils.notifier import check_channels
    return jsonify(check_channels())
