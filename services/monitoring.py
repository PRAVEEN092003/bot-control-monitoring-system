"""
services/monitoring.py — Security event logging service.

Provides a single log_event() function that any route or service can
call to persist an ActivityLog record.  All database writes go through
this module so logging is consistent across the application.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from flask import current_app, request

from extensions import db
from models.activity import ActivityLog, ActivityStatus, EventType, RiskLevel

logger = logging.getLogger(__name__)


def log_event(
    event_type: str,
    description: str = "",
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    risk_score: int = 0,
    status: str = ActivityStatus.SUCCESS,
    endpoint: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Optional[ActivityLog]:
    """
    Persist a security-relevant event to the activity log.

    Parameters
    ----------
    event_type  : One of the EventType constants.
    description : Human-readable description of the event.
    user_id     : ID of the authenticated user (None for anonymous events).
    ip_address  : Client IP — auto-detected from request if omitted.
    risk_score  : Numeric risk contribution of this event (0–100).
    status      : One of ActivityStatus constants.
    endpoint    : URL endpoint (auto-detected if omitted).
    user_agent  : User-Agent string (auto-detected if omitted).

    Returns
    -------
    The saved ActivityLog instance, or None if logging failed.
    """
    try:
        # Auto-detect request context values when available
        if ip_address is None:
            try:
                ip_address = _get_client_ip()
            except RuntimeError:
                ip_address = "unknown"

        if endpoint is None:
            try:
                endpoint = request.path
            except RuntimeError:
                endpoint = None

        if user_agent is None:
            try:
                user_agent = request.headers.get("User-Agent", "")[:512]
            except RuntimeError:
                user_agent = None

        risk_level = ActivityLog.compute_risk_level(risk_score)

        entry = ActivityLog(
            event_type=event_type,
            description=description,
            user_id=user_id,
            ip_address=ip_address,
            risk_score=risk_score,
            risk_level=risk_level,
            status=status,
            endpoint=endpoint,
            user_agent=user_agent,
        )
        db.session.add(entry)
        db.session.commit()

        # Mirror important events to the app logger
        log_msg = (
            f"[SECURITY] {event_type.upper()} | ip={ip_address} "
            f"user_id={user_id} risk={risk_score} status={status} | {description}"
        )
        if risk_level == RiskLevel.HIGH_RISK:
            logger.warning(log_msg)
        elif risk_level == RiskLevel.SUSPICIOUS:
            logger.info(log_msg)
        else:
            logger.debug(log_msg)

        return entry

    except Exception as exc:
        # Logging must never crash the application
        logger.error(f"Failed to write activity log: {exc}", exc_info=True)
        try:
            db.session.rollback()
        except Exception:
            pass
        return None


def _get_client_ip() -> str:
    """
    Return the real client IP, respecting X-Forwarded-For when present.
    Only trust the first (leftmost) value from the header.
    """
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        # Take only the first IP in the chain (nearest client)
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


# ── Convenience wrappers ───────────────────────────────────────────────────────

def log_login_success(user_id: int, username: str) -> None:
    log_event(
        event_type=EventType.LOGIN_SUCCESS,
        description=f"User '{username}' logged in successfully.",
        user_id=user_id,
        status=ActivityStatus.SUCCESS,
        risk_score=0,
    )


def log_login_failure(
    email: str,
    reason: str = "Invalid credentials",
    user_id: Optional[int] = None,
) -> None:
    if user_id is None and email:
        try:
            from models.user import User
            u = User.query.filter_by(email=email.strip().lower()).first()
            if u:
                user_id = u.id
        except Exception:
            pass

    entry = log_event(
        event_type=EventType.LOGIN_FAILURE,
        description=f"Failed login attempt for email '{email}': {reason}.",
        user_id=user_id,
        status=ActivityStatus.FAILURE,
        risk_score=20,  # Per Phase 5 spec; baseline score
    )

    if entry:
        try:
            from services.bot_detector import analyze_behavior, update_activity_risk
            analysis = analyze_behavior(ip_address=entry.ip_address, user_id=user_id)
            if analysis and "risk_score" in analysis:
                update_activity_risk(entry.id, analysis["risk_score"])
        except Exception as exc:
            logger.error(f"Failed to update risk for login failure: {exc}", exc_info=True)


def log_logout(user_id: int, username: str) -> None:
    log_event(
        event_type=EventType.LOGOUT,
        description=f"User '{username}' logged out.",
        user_id=user_id,
        status=ActivityStatus.SUCCESS,
        risk_score=0,
    )


def log_register_success(user_id: int, username: str) -> None:
    log_event(
        event_type=EventType.REGISTER_SUCCESS,
        description=f"New account created for '{username}'.",
        user_id=user_id,
        status=ActivityStatus.SUCCESS,
        risk_score=0,
    )


def log_register_failure(username: str, reason: str) -> None:
    log_event(
        event_type=EventType.REGISTER_FAILURE,
        description=f"Registration failed for '{username}': {reason}.",
        status=ActivityStatus.FAILURE,
        risk_score=0,
    )


def log_captcha_success(
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
) -> None:
    log_event(
        event_type=EventType.CAPTCHA_SUCCESS,
        description="CAPTCHA challenge completed successfully.",
        user_id=user_id,
        ip_address=ip_address,
        status=ActivityStatus.SUCCESS,
        risk_score=0,
    )


def log_captcha_failure(
    user_id: Optional[int] = None,
    reason: str = "Incorrect answer",
    ip_address: Optional[str] = None,
) -> None:
    entry = log_event(
        event_type=EventType.CAPTCHA_FAILURE,
        description=f"CAPTCHA challenge failed: {reason}.",
        user_id=user_id,
        ip_address=ip_address,
        status=ActivityStatus.FAILURE,
        risk_score=25,
    )

    if entry:
        try:
            from services.bot_detector import analyze_behavior, update_activity_risk
            analysis = analyze_behavior(ip_address=entry.ip_address, user_id=user_id)
            if analysis and "risk_score" in analysis:
                update_activity_risk(entry.id, analysis["risk_score"])
        except Exception as exc:
            logger.error(f"Failed to update risk for captcha failure: {exc}", exc_info=True)

