"""
services/bot_detector.py — Bot and suspicious automated behavior detection.

Analyzes ActivityLog history to detect:
1. Repeated failed logins
2. Repeated CAPTCHA failures
3. Excessive requests/events
4. Rapid repeated activity (bursts)

Integrates with risk_engine.py to compute risk scores and update ActivityLog records.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from typing import Dict, List, Optional, Tuple

from extensions import db
from models.activity import ActivityLog, ActivityStatus, EventType, RiskLevel
from services.monitoring import log_event
from services.risk_engine import (
    calculate_risk_score,
    compute_risk_level,
)

logger = logging.getLogger(__name__)

# Default detection thresholds
DEFAULT_FAILED_LOGIN_THRESHOLD = 3       # >= 3 failed logins in window
DEFAULT_CAPTCHA_FAILURE_THRESHOLD = 3     # >= 3 captcha failures in window
DEFAULT_EXCESSIVE_REQ_THRESHOLD = 20      # >= 20 events in 60s
DEFAULT_RAPID_BURST_THRESHOLD = 5         # >= 5 events in 10s


# ── Query Helper ───────────────────────────────────────────────────────────────

def _get_recent_logs(
    ip_address: Optional[str] = None,
    user_id: Optional[int] = None,
    window_seconds: int = 900,
    event_type: Optional[str] = None,
) -> List[ActivityLog]:
    """Query recent ActivityLog records within a sliding time window."""
    since = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    query = ActivityLog.query.filter(ActivityLog.created_at >= since)

    if ip_address and user_id:
        query = query.filter(
            (ActivityLog.ip_address == ip_address) | (ActivityLog.user_id == user_id)
        )
    elif ip_address:
        query = query.filter_by(ip_address=ip_address)
    elif user_id:
        query = query.filter_by(user_id=user_id)
    else:
        return []

    if event_type:
        query = query.filter_by(event_type=event_type)

    return query.order_by(ActivityLog.created_at.desc()).all()


# ── Granular Detection Checks ──────────────────────────────────────────────────

def check_repeated_failed_logins(
    ip_address: Optional[str] = None,
    user_id: Optional[int] = None,
    window_seconds: int = 900,
    threshold: int = DEFAULT_FAILED_LOGIN_THRESHOLD,
) -> Dict:
    """
    Check 1: Detect repeated failed login attempts.
    """
    logs = _get_recent_logs(
        ip_address=ip_address,
        user_id=user_id,
        window_seconds=window_seconds,
        event_type=EventType.LOGIN_FAILURE,
    )
    count = len(logs)
    triggered = count >= threshold
    return {
        "check": "repeated_failed_logins",
        "triggered": triggered,
        "count": count,
        "threshold": threshold,
        "window_seconds": window_seconds,
    }


def check_repeated_captcha_failures(
    ip_address: Optional[str] = None,
    user_id: Optional[int] = None,
    window_seconds: int = 900,
    threshold: int = DEFAULT_CAPTCHA_FAILURE_THRESHOLD,
) -> Dict:
    """
    Check 2: Detect repeated CAPTCHA verification failures.
    """
    logs = _get_recent_logs(
        ip_address=ip_address,
        user_id=user_id,
        window_seconds=window_seconds,
        event_type=EventType.CAPTCHA_FAILURE,
    )
    count = len(logs)
    triggered = count >= threshold
    return {
        "check": "repeated_captcha_failures",
        "triggered": triggered,
        "count": count,
        "threshold": threshold,
        "window_seconds": window_seconds,
    }


def check_excessive_activity(
    ip_address: Optional[str] = None,
    user_id: Optional[int] = None,
    window_seconds: int = 60,
    threshold: int = DEFAULT_EXCESSIVE_REQ_THRESHOLD,
) -> Dict:
    """
    Check 3: Detect excessive overall request volume in a standard window.
    """
    logs = _get_recent_logs(
        ip_address=ip_address,
        user_id=user_id,
        window_seconds=window_seconds,
    )
    count = len(logs)
    triggered = count >= threshold
    return {
        "check": "excessive_activity",
        "triggered": triggered,
        "count": count,
        "threshold": threshold,
        "window_seconds": window_seconds,
    }


def check_rapid_repeated_activity(
    ip_address: Optional[str] = None,
    user_id: Optional[int] = None,
    window_seconds: int = 10,
    threshold: int = DEFAULT_RAPID_BURST_THRESHOLD,
) -> Dict:
    """
    Check 4: Detect rapid automated request bursts in a very short window.
    """
    logs = _get_recent_logs(
        ip_address=ip_address,
        user_id=user_id,
        window_seconds=window_seconds,
    )
    count = len(logs)
    triggered = count >= threshold
    return {
        "check": "rapid_repeated_activity",
        "triggered": triggered,
        "count": count,
        "threshold": threshold,
        "window_seconds": window_seconds,
    }


# ── Behavioral Analysis & Score Calculation ───────────────────────────────────

def analyze_behavior(
    ip_address: Optional[str] = None,
    user_id: Optional[int] = None,
    window_minutes: int = 15,
) -> Dict:
    """
    Evaluate client activity across all 4 detection checks and compute risk score.

    Returns
    -------
    dict
        {
            "ip_address": str,
            "user_id": int,
            "risk_score": int (0–100),
            "risk_level": "NORMAL" | "SUSPICIOUS" | "HIGH_RISK",
            "is_suspicious": bool,
            "is_high_risk": bool,
            "flags": list[str],
            "breakdown": dict,
            "checks": dict,
        }
    """
    window_sec = window_minutes * 60

    failed_login_res = check_repeated_failed_logins(
        ip_address=ip_address, user_id=user_id, window_seconds=window_sec
    )
    captcha_res = check_repeated_captcha_failures(
        ip_address=ip_address, user_id=user_id, window_seconds=window_sec
    )
    excessive_res = check_excessive_activity(
        ip_address=ip_address, user_id=user_id, window_seconds=60
    )
    rapid_res = check_rapid_repeated_activity(
        ip_address=ip_address, user_id=user_id, window_seconds=10
    )

    flags = []
    if failed_login_res["triggered"]:
        flags.append(f"repeated_failed_logins ({failed_login_res['count']})")
    if captcha_res["triggered"]:
        flags.append(f"repeated_captcha_failures ({captcha_res['count']})")
    if excessive_res["triggered"]:
        flags.append(f"excessive_activity ({excessive_res['count']}/60s)")
    if rapid_res["triggered"]:
        flags.append(f"rapid_repeated_activity ({rapid_res['count']}/10s)")

    # Repeated suspicious activity applies when rapid bursts occur or multiple anomalous checks trigger
    has_repeated_suspicious = bool(
        rapid_res["triggered"] or (len(flags) >= 2)
    )

    score, level, breakdown = calculate_risk_score(
        failed_logins=failed_login_res["count"],
        captcha_failures=captcha_res["count"],
        has_excessive_activity=excessive_res["triggered"],
        has_repeated_suspicious=has_repeated_suspicious,
    )

    return {
        "ip_address": ip_address,
        "user_id": user_id,
        "risk_score": score,
        "risk_level": level,
        "is_suspicious": level in (RiskLevel.SUSPICIOUS, RiskLevel.HIGH_RISK),
        "is_high_risk": level == RiskLevel.HIGH_RISK,
        "flags": flags,
        "breakdown": breakdown,
        "checks": {
            "failed_logins": failed_login_res,
            "captcha_failures": captcha_res,
            "excessive_activity": excessive_res,
            "rapid_activity": rapid_res,
        },
    }


# ── ActivityLog Risk Updates & Bot Event Recording ─────────────────────────────

def update_activity_risk(log_id: int, new_score: int) -> Optional[ActivityLog]:
    """Update an ActivityLog record with a new calculated risk score and level."""
    entry = db.session.get(ActivityLog, log_id)
    if not entry:
        return None

    entry.risk_score = max(0, min(100, int(new_score)))
    entry.risk_level = compute_risk_level(entry.risk_score)
    try:
        db.session.commit()
        return entry
    except Exception as exc:
        db.session.rollback()
        logger.error(f"Failed to update ActivityLog {log_id} risk: {exc}")
        return None


def record_bot_detection(
    ip_address: str,
    user_id: Optional[int] = None,
    analysis_result: Optional[Dict] = None,
    endpoint: Optional[str] = None,
) -> Optional[ActivityLog]:
    """
    Create a BOT_DETECTED audit entry in ActivityLog when automated bot behavior is identified.
    """
    if analysis_result is None:
        analysis_result = analyze_behavior(ip_address=ip_address, user_id=user_id)

    flags_str = ", ".join(analysis_result.get("flags", [])) or "Suspicious pattern detected"
    score = analysis_result.get("risk_score", 0)

    return log_event(
        event_type=EventType.BOT_DETECTED,
        description=f"Automated bot behavior detected: {flags_str}",
        user_id=user_id,
        ip_address=ip_address,
        risk_score=score,
        status=ActivityStatus.WARNING if score < 61 else ActivityStatus.BLOCKED,
        endpoint=endpoint,
    )
