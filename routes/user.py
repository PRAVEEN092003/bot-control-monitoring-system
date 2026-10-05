"""
routes/user.py — Authenticated user dashboard and activity monitoring blueprint.

All routes in this blueprint require login (@login_required).
Flask-Login redirects unauthenticated requests to auth.login.
"""

import logging

from flask import Blueprint, render_template, request
from flask_login import current_user, login_required

from models.activity import ActivityLog, EventType

logger = logging.getLogger(__name__)

user_bp = Blueprint("user", __name__, url_prefix="/user")

# Available event types for user-friendly filtering
USER_EVENT_TYPES = [
    (EventType.LOGIN_SUCCESS, "Login Success"),
    (EventType.LOGIN_FAILURE, "Login Failure"),
    (EventType.LOGOUT, "Logout"),
    (EventType.REGISTER_SUCCESS, "Account Registration"),
    (EventType.CAPTCHA_SUCCESS, "CAPTCHA Solved"),
    (EventType.CAPTCHA_FAILURE, "CAPTCHA Failed"),
]


@user_bp.route("/dashboard")
@login_required
def dashboard():
    """
    Authenticated user dashboard.

    Shows:
    - Account overview
    - Recent activity (last 10 events for this user)
    - Security status (failed login count)
    """
    selected_filter = request.args.get("event_type", "").strip()

    query = ActivityLog.query.filter_by(user_id=current_user.id)
    if selected_filter and selected_filter != "all":
        query = query.filter_by(event_type=selected_filter)

    recent_activity = query.order_by(ActivityLog.created_at.desc()).limit(10).all()

    total_failed_logins = ActivityLog.query.filter_by(
        user_id=current_user.id,
        event_type=EventType.LOGIN_FAILURE,
    ).count()

    logger.debug(f"Dashboard accessed by user: {current_user.username}")
    return render_template(
        "dashboard.html",
        user=current_user,
        recent_activity=recent_activity,
        total_failed_logins=total_failed_logins,
        event_types=USER_EVENT_TYPES,
        selected_filter=selected_filter,
    )



@user_bp.route("/activity")
@login_required
def activity():
    """
    Detailed security activity log page for the current user.

    Supports:
    - Filtering by event_type query parameter
    - Showing audit context (timestamp, status, risk level, IP address, description)
    """
    selected_filter = request.args.get("event_type", "").strip()

    query = ActivityLog.query.filter_by(user_id=current_user.id)
    if selected_filter and selected_filter != "all":
        query = query.filter_by(event_type=selected_filter)

    events = query.order_by(ActivityLog.created_at.desc()).limit(100).all()
    total_count = query.count()

    logger.debug(
        f"Activity log accessed by user: {current_user.username} "
        f"(filter={selected_filter or 'all'}, count={len(events)})"
    )

    return render_template(
        "user_activity.html",
        user=current_user,
        events=events,
        total_count=total_count,
        event_types=USER_EVENT_TYPES,
        selected_filter=selected_filter,
    )


# ── Health-check (preserved) ──────────────────────────────────────────────────

@user_bp.route("/ping")
def ping():
    """Health-check endpoint."""
    return {"status": "user blueprint registered", "phase": 2}
