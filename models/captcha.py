"""
models/captcha.py — CAPTCHA attempt tracking model.

Stores a historical record of every CAPTCHA attempt (pass or fail).
The actual CAPTCHA answer is NEVER persisted here — only the outcome.
The live CAPTCHA text lives only in the encrypted session and is
short-lived (see CAPTCHA_EXPIRY_SECONDS).
"""

from datetime import datetime, timezone
from extensions import db


class CaptchaAttempt(db.Model):
    """Records the outcome of a single CAPTCHA challenge."""

    __tablename__ = "captcha_attempts"

    # ── Primary fields ─────────────────────────────────────────────────────────
    id = db.Column(db.Integer, primary_key=True)

    # Optional user link (may be None for unauthenticated attempts)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # ── Request context ────────────────────────────────────────────────────────
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    user_agent = db.Column(db.String(512), nullable=True)

    # ── Outcome ────────────────────────────────────────────────────────────────
    success = db.Column(db.Boolean, nullable=False, default=False)

    # ── Timestamp ─────────────────────────────────────────────────────────────
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # ── Helpers ────────────────────────────────────────────────────────────────
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "ip_address": self.ip_address,
            "success": self.success,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        outcome = "PASS" if self.success else "FAIL"
        return (
            f"<CaptchaAttempt id={self.id} ip={self.ip_address!r} "
            f"outcome={outcome}>"
        )
