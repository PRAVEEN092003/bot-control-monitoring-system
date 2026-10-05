"""
routes/admin.py — Cybersecurity monitoring and administration dashboard.

Endpoints
---------
GET  /admin/              — Main Admin Dashboard overview with stats & Chart.js charts
GET  /admin/dashboard     — Alias for main dashboard
GET  /admin/logs          — Security audit log viewer with multi-criteria filtering
GET  /admin/users         — User management overview
GET  /admin/blocked-ips   — Active and historical blocked IP management
POST /admin/block-ip      — Manually block an IP address
POST /admin/unblock-ip    — Manually unblock an IP address
GET  /admin/api/stats     — JSON statistics API endpoint
GET  /admin/ping          — Health-check endpoint

Authorization
-------------
All admin routes require an authenticated user with `is_admin=True` (@admin_required).
Non-admin and anonymous users receive 403 / 302 redirects.
"""

from datetime import datetime, timezone
from functools import wraps
import logging
from typing import Dict

from flask import (
    Blueprint,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import func

from extensions import db
from models.activity import ActivityLog, ActivityStatus, EventType, RiskLevel
from models.blocked_ip import BlockedIP
from models.captcha import CaptchaAttempt
from models.user import User
from services.ip_blocker import block_ip, get_active_blocks, unblock_ip

logger = logging.getLogger(__name__)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


# ── Authorization Decorator ───────────────────────────────────────────────────

def admin_required(f):
    """Decorator ensuring that only authenticated administrators can access the endpoint."""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            logger.warning(
                f"Unauthorized admin access attempt by user_id={getattr(current_user, 'id', 'anon')}"
            )
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# ── Helper: Aggregate Statistics ───────────────────────────────────────────────

def _get_admin_metrics() -> Dict:
    """Calculate summary statistics and chart datasets for the admin dashboard."""
    total_users = User.query.count()
    total_events = ActivityLog.query.count()

    captcha_successes = CaptchaAttempt.query.filter_by(success=True).count()
    captcha_failures = CaptchaAttempt.query.filter_by(success=False).count()

    suspicious_count = ActivityLog.query.filter_by(risk_level=RiskLevel.SUSPICIOUS).count()
    high_risk_count = ActivityLog.query.filter_by(risk_level=RiskLevel.HIGH_RISK).count()

    active_blocks = get_active_blocks()
    blocked_ips_count = len(active_blocks)

    # Event distribution
    event_counts_raw = (
        db.session.query(ActivityLog.event_type, func.count(ActivityLog.id))
        .group_by(ActivityLog.event_type)
        .all()
    )
    event_distribution = {ev: count for ev, count in event_counts_raw}

    # Risk level distribution (ensure all 3 levels exist even if 0)
    risk_counts_raw = (
        db.session.query(ActivityLog.risk_level, func.count(ActivityLog.id))
        .group_by(ActivityLog.risk_level)
        .all()
    )
    risk_distribution = {
        RiskLevel.NORMAL: 0,
        RiskLevel.SUSPICIOUS: 0,
        RiskLevel.HIGH_RISK: 0,
    }
    for r_level, count in risk_counts_raw:
        if r_level in risk_distribution:
            risk_distribution[r_level] = count

    return {
        "total_users": total_users,
        "total_events": total_events,
        "captcha_successes": captcha_successes,
        "captcha_failures": captcha_failures,
        "suspicious_count": suspicious_count,
        "high_risk_count": high_risk_count,
        "blocked_ips_count": blocked_ips_count,
        "event_distribution": event_distribution,
        "risk_distribution": risk_distribution,
        "captcha_stats": {
            "success": captcha_successes,
            "failure": captcha_failures,
        },
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@admin_bp.route("/")
@admin_bp.route("/dashboard")
@admin_required
def dashboard():
    """
    Main Administration and Cybersecurity Monitoring Dashboard.
    """
    metrics = _get_admin_metrics()

    # Filtering for recent events table
    event_type = request.args.get("event_type", "").strip()
    risk_level = request.args.get("risk_level", "").strip()
    search = request.args.get("q", "").strip()

    query = ActivityLog.query
    if event_type and event_type != "all":
        query = query.filter_by(event_type=event_type)
    if risk_level and risk_level != "all":
        query = query.filter_by(risk_level=risk_level)
    if search:
        query = query.filter(
            (ActivityLog.ip_address.ilike(f"%{search}%"))
            | (ActivityLog.description.ilike(f"%{search}%"))
        )

    recent_events = query.order_by(ActivityLog.created_at.desc()).limit(15).all()
    active_blocks = get_active_blocks()[:5]

    return render_template(
        "admin/dashboard.html",
        metrics=metrics,
        recent_events=recent_events,
        active_blocks=active_blocks,
        selected_event_type=event_type,
        selected_risk_level=risk_level,
        search_query=search,
    )


@admin_bp.route("/logs")
@admin_required
def logs():
    """
    Comprehensive Security Audit Log with search, multi-criteria filters,
    date-range filtering, and pagination.
    """
    event_type = request.args.get("event_type", "").strip()
    risk_level = request.args.get("risk_level", "").strip()
    status_filter = request.args.get("status", "").strip()
    ip_filter = request.args.get("ip", "").strip()
    search = request.args.get("q", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 25, type=int)
    if per_page < 5:
        per_page = 5
    elif per_page > 100:
        per_page = 100

    query = ActivityLog.query

    # 1. Event Type filter
    if event_type and event_type != "all":
        query = query.filter_by(event_type=event_type)

    # 2. Risk Level filter
    if risk_level and risk_level != "all":
        query = query.filter_by(risk_level=risk_level)

    # 3. Status filter
    if status_filter and status_filter != "all":
        query = query.filter_by(status=status_filter)

    # 4. IP address filter
    if ip_filter:
        query = query.filter(ActivityLog.ip_address.ilike(f"%{ip_filter}%"))

    # 5. Keyword search (IP, description, endpoint, user_agent)
    if search:
        query = query.filter(
            (ActivityLog.ip_address.ilike(f"%{search}%"))
            | (ActivityLog.description.ilike(f"%{search}%"))
            | (ActivityLog.endpoint.ilike(f"%{search}%"))
            | (ActivityLog.user_agent.ilike(f"%{search}%"))
        )

    # 6. Date-range filter (date_from, date_to)
    if date_from:
        try:
            dt_from = datetime.strptime(date_from, "%Y-%m-%d")
            query = query.filter(ActivityLog.created_at >= dt_from)
        except ValueError:
            try:
                dt_from = datetime.fromisoformat(date_from)
                query = query.filter(ActivityLog.created_at >= dt_from)
            except ValueError:
                pass

    if date_to:
        try:
            dt_to = datetime.strptime(date_to, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59, microsecond=999999
            )
            query = query.filter(ActivityLog.created_at <= dt_to)
        except ValueError:
            try:
                dt_to = datetime.fromisoformat(date_to)
                query = query.filter(ActivityLog.created_at <= dt_to)
            except ValueError:
                pass

    # Pagination
    pagination = query.order_by(ActivityLog.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    events = pagination.items

    return render_template(
        "admin/logs.html",
        events=events,
        pagination=pagination,
        total_matched=pagination.total,
        selected_event_type=event_type,
        selected_risk_level=risk_level,
        selected_status=status_filter,
        ip_filter=ip_filter,
        search_query=search,
        date_from=date_from,
        date_to=date_to,
        per_page=per_page,
    )


@admin_bp.route("/users")
@admin_required
def users():
    """
    User account directory and security overview.
    """
    user_list = User.query.order_by(User.created_at.desc()).all()
    return render_template(
        "admin/users.html",
        users=user_list,
        total_users=len(user_list),
    )


@admin_bp.route("/blocked-ips")
@admin_required
def blocked_ips():
    """
    Active and historical IP block management.
    """
    blocks = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
    active_blocks = get_active_blocks()
    return render_template(
        "admin/blocked_ips.html",
        blocks=blocks,
        active_count=len(active_blocks),
    )


@admin_bp.route("/block-ip", methods=["POST"])
@admin_required
def manual_block_ip():
    """Manually add a temporary IP block."""
    ip_addr = request.form.get("ip_address", "").strip()
    reason = request.form.get("reason", "Manual administrator block").strip()
    try:
        duration = int(request.form.get("duration", 30))
    except (ValueError, TypeError):
        duration = 30

    if not ip_addr:
        flash("IP address is required.", "danger")
        return redirect(url_for("admin.blocked_ips"))

    block_ip(ip_address=ip_addr, reason=reason, duration_minutes=duration, risk_score=80)
    flash(f"IP {ip_addr} has been temporarily blocked for {duration} minutes.", "success")
    return redirect(url_for("admin.blocked_ips"))


@admin_bp.route("/unblock-ip", methods=["POST"])
@admin_required
def manual_unblock_ip():
    """Manually remove an active IP block."""
    ip_addr = request.form.get("ip_address", "").strip()
    note = request.form.get("note", "Manually unblocked by admin").strip()

    if not ip_addr:
        flash("IP address is required.", "danger")
        return redirect(url_for("admin.blocked_ips"))

    unblocked = unblock_ip(ip_address=ip_addr, admin_note=note)
    if unblocked:
        flash(f"IP {ip_addr} has been unblocked.", "success")
    else:
        flash(f"No active block found for IP {ip_addr}.", "info")

    return redirect(url_for("admin.blocked_ips"))


@admin_bp.route("/api/stats")
@admin_required
def api_stats():
    """JSON API providing live system security statistics."""
    metrics = _get_admin_metrics()
    return jsonify(metrics)


@admin_bp.route("/ping")
def ping():
    """Health-check endpoint."""
    return jsonify({"status": "admin blueprint active", "phase": 7})
