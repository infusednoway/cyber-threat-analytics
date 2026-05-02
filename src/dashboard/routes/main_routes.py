from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify

from src.auth.auth import login_required, role_required, get_current_user, ROLE_ADMIN, ROLE_ANALYST
from src.database.db import (
    get_cves, get_cve_by_id, get_news, get_exploits, get_exploit_by_id,
    get_alert_log, mark_alerts_read, log_alert,
    get_reports, get_report_by_id, create_report,
    get_watchlist, add_to_watchlist, remove_from_watchlist,
    get_tags, get_cve_tags, add_tag_to_cve,
    get_all_users, update_user_role, toggle_user_active, get_total_counts,
)
from src.models.alerter import get_alerts
from src.models.predictor import get_timeline_data, predict_next_days, get_weekly_growth, get_severity_distribution
from src.models.classifier import get_top_features
from src.models.model_comparison import load_comparison

main_bp = Blueprint("main_bp", __name__)


@main_bp.route("/")
@login_required
def dashboard():
    user = get_current_user()
    alerts = get_alerts()
    cve_total, news_total, exploit_total = get_total_counts()
    severity = get_severity_distribution()
    return render_template("pages/dashboard.html",
        user=user, alerts=alerts,
        cve_total=cve_total, news_total=news_total, exploit_total=exploit_total,
        severity=severity, growth=get_weekly_growth())


@main_bp.route("/cves")
@login_required
def cve_list():
    user = get_current_user()
    severity = request.args.get("severity", "")
    search   = request.args.get("search", "")
    cves = get_cves(limit=200, severity=severity or None, search=search or None)
    return render_template("pages/cve_list.html", user=user, cves=cves,
                           severity=severity, search=search)


@main_bp.route("/cves/<cve_id>")
@login_required
def cve_detail(cve_id):
    user = get_current_user()
    cve  = get_cve_by_id(cve_id)
    if not cve:
        return render_template("pages/404.html", user=user), 404
    tags = get_cve_tags(cve_id)
    all_tags = get_tags()
    watchlist = get_watchlist(user["user_id"]) if user else []
    in_watchlist = any(w["cve_id"] == cve_id for w in watchlist)
    return render_template("pages/cve_detail.html", user=user, cve=cve,
                           tags=tags, all_tags=all_tags, in_watchlist=in_watchlist)


@main_bp.route("/cves/<cve_id>/watchlist", methods=["POST"])
@login_required
def toggle_watchlist(cve_id):
    user  = get_current_user()
    notes = request.form.get("notes", "")
    watchlist = get_watchlist(user["user_id"])
    if any(w["cve_id"] == cve_id for w in watchlist):
        remove_from_watchlist(user["user_id"], cve_id)
    else:
        add_to_watchlist(user["user_id"], cve_id, notes)
    return redirect(url_for("main_bp.cve_detail", cve_id=cve_id))


@main_bp.route("/cves/<cve_id>/tag", methods=["POST"])
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def tag_cve(cve_id):
    tag_id = request.form.get("tag_id", type=int)
    if tag_id:
        add_tag_to_cve(cve_id, tag_id)
    return redirect(url_for("main_bp.cve_detail", cve_id=cve_id))


@main_bp.route("/exploits")
@login_required
def exploit_list():
    user = get_current_user()
    exploit_type = request.args.get("type", "")
    exploits = get_exploits(limit=200, exploit_type=exploit_type or None)
    type_counts = {}
    for e in get_exploits(limit=500):
        t = e["exploit_type"]
        type_counts[t] = type_counts.get(t, 0) + 1
    return render_template("pages/exploit_list.html", user=user,
                           exploits=exploits, exploit_type=exploit_type,
                           type_counts=type_counts)


@main_bp.route("/exploits/<int:exploit_id>")
@login_required
def exploit_detail(exploit_id):
    user    = get_current_user()
    exploit = get_exploit_by_id(exploit_id)
    if not exploit:
        return render_template("pages/404.html", user=user), 404
    related_cve = get_cve_by_id(exploit["cve_id"]) if exploit.get("cve_id") else None
    return render_template("pages/exploit_detail.html", user=user,
                           exploit=exploit, related_cve=related_cve)


@main_bp.route("/news")
@login_required
def news_list():
    user   = get_current_user()
    source = request.args.get("source", "")
    items  = get_news(limit=100, source=source or None)
    return render_template("pages/news_list.html", user=user,
                           items=items, source=source)


@main_bp.route("/alerts")
@login_required
def alerts_page():
    user    = get_current_user()
    active  = get_alerts()
    history = get_alert_log(limit=100)
    mark_alerts_read()
    return render_template("pages/alerts.html", user=user,
                           active=active, history=history)


@main_bp.route("/predictions")
@login_required
def predictions_page():
    user        = get_current_user()
    timeline    = get_timeline_data()
    predictions = predict_next_days(30)
    return render_template("pages/predictions.html", user=user,
                           timeline=timeline, predictions=predictions)


@main_bp.route("/reports")
@login_required
def reports_list():
    user    = get_current_user()
    reports = get_reports()
    return render_template("pages/reports_list.html", user=user, reports=reports)


@main_bp.route("/reports/new", methods=["GET", "POST"])
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def report_new():
    user = get_current_user()
    if request.method == "POST":
        severity = get_severity_distribution()
        cve_total, _, _ = get_total_counts()
        report_id = create_report({
            "title":      request.form.get("title", "Отчёт"),
            "created_by": user["user_id"],
            "date_from":  request.form.get("date_from", ""),
            "date_to":    request.form.get("date_to", ""),
            "total_cves": cve_total,
            "critical":   severity.get("CRITICAL", 0),
            "high":       severity.get("HIGH", 0),
            "medium":     severity.get("MEDIUM", 0),
            "low":        severity.get("LOW", 0),
            "notes":      request.form.get("notes", ""),
        })
        log_alert("info", f"Создан новый отчёт #{report_id}")
        return redirect(url_for("main_bp.report_detail", report_id=report_id))
    return render_template("pages/report_new.html", user=user)


@main_bp.route("/reports/<int:report_id>")
@login_required
def report_detail(report_id):
    user   = get_current_user()
    report = get_report_by_id(report_id)
    if not report:
        return render_template("pages/404.html", user=user), 404
    return render_template("pages/report_detail.html", user=user, report=report)


@main_bp.route("/watchlist")
@login_required
def watchlist_page():
    user  = get_current_user()
    items = get_watchlist(user["user_id"])
    return render_template("pages/watchlist.html", user=user, items=items)


@main_bp.route("/models")
@login_required
def models_page():
    user       = get_current_user()
    comparison = load_comparison()
    features   = get_top_features(20)
    return render_template("pages/models.html", user=user,
                           comparison=comparison, features=features)


@main_bp.route("/admin/users")
@role_required(ROLE_ADMIN)
def admin_users():
    user  = get_current_user()
    users = get_all_users()
    return render_template("pages/admin_users.html", user=user, users=users)


@main_bp.route("/admin/users/<int:uid>/role", methods=["POST"])
@role_required(ROLE_ADMIN)
def admin_change_role(uid):
    role_id = request.form.get("role_id", type=int)
    if role_id in (1, 2, 3):
        update_user_role(uid, role_id)
    return redirect(url_for("main_bp.admin_users"))


@main_bp.route("/admin/users/<int:uid>/toggle", methods=["POST"])
@role_required(ROLE_ADMIN)
def admin_toggle_user(uid):
    toggle_user_active(uid)
    return redirect(url_for("main_bp.admin_users"))


@main_bp.route("/profile")
@login_required
def profile():
    from src.database.db import get_user_by_id
    user     = get_current_user()
    userdata = get_user_by_id(user["user_id"])
    watchlist = get_watchlist(user["user_id"])
    return render_template("pages/profile.html", user=user,
                           userdata=userdata, watchlist=watchlist)


@main_bp.route("/settings")
@role_required(ROLE_ADMIN)
def settings_page():
    user = get_current_user()
    return render_template("pages/settings.html", user=user)
