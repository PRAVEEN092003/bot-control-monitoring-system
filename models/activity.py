"""
models/activity.py — Security event / activity log model.

Every noteworthy security event (login, CAPTCHA, rate-limit violation,
suspicious request, IP block …) is recorded here with full context so the
admin dashboard has a rich audit trail.
"""

from datetime import datetime, timezone
from extensions import db


# ── Enumeration constants (stored as strings for readability) ──────────────────

class EventType:
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    REGISTER_SUCCESS = "register_success"
    REGISTER_FAILURE = "register_failure"
    CAPTCHA_SUCCESS = "captcha_success"
    CAPTCHA_FAILURE = "captcha_failure"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_REQUEST = "suspicious_request"
    IP_BLOCKED = "ip_blocked"
    IP_UNBLOCKED = "ip_unblocked"
    ADMIN_ACCESS = "admin_access"
    BOT_DETECTED = "bot_detected"
    RISK_ESCALATED = "risk_escalated"


class RiskLevel:
    NORMAL = "NORMAL"        # score 0–30
    SUSPICIOUS = "SUSPICIOUS"  # score 31–60
    HIGH_RISK = "HIGH_RISK"  # score 61–100


class ActivityStatus:
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    WARNING = "warning"


class ActivityLog(db.Model):
    """Immutable audit record for a single security-relevant event."""

    __tablename__ = "activity_logs"

    # ── Primary fields ─────────────────────────────────────────────────────────
    id = db.Column(db.Integer, primary_key=True)

    # Optional link to a registered user (nullable for unauthenticated events)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # ── Request context ────────────────────────────────────────────────────────
    ip_address = db.Column(db.String(45), nullable=False, index=True)  # supports IPv6
    user_agent = db.Column(db.String(512), nullable=True)
    endpoint = db.Column(db.String(256), nullable=True)

    # ── Event classification ───────────────────────────────────────────────────
    event_type = db.Column(db.String(64), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)

    # ── Risk assessment ────────────────────────────────────────────────────────
    risk_score = db.Column(db.Integer, default=0, nullable=False)
    risk_level = db.Column(
        db.String(16), default=RiskLevel.NORMAL, nullable=False, index=True
    )

    # ── Outcome ────────────────────────────────────────────────────────────────
    status = db.Column(
        db.String(16), default=ActivityStatus.SUCCESS, nullable=False
    )

    # ── Timestamp ─────────────────────────────────────────────────────────────
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # ── Helpers ────────────────────────────────────────────────────────────────
    @staticmethod
    def compute_risk_level(score: int) -> str:
        """Map a numeric risk score to its string level."""
        if score >= 61:
            return RiskLevel.HIGH_RISK
        if score >= 31:
            return RiskLevel.SUSPICIOUS
        return RiskLevel.NORMAL

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "endpoint": self.endpoint,
            "event_type": self.event_type,
            "description": self.description,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<ActivityLog id={self.id} type={self.event_type!r} "
            f"ip={self.ip_address!r} risk={self.risk_score}>"
        )
