"""
models/blocked_ip.py — Temporary IP block model.

When the risk engine determines that an IP has exceeded the HIGH_RISK
threshold, a BlockedIP record is created with an expiry time.  The block
is automatically treated as inactive once expires_at passes.

No IP is blocked permanently by the automated system — all blocks have an
expiry.  Administrators can manually deactivate a block early.
"""

from datetime import datetime, timezone
from extensions import db


class BlockedIP(db.Model):
    """Represents a temporarily blocked IP address."""

    __tablename__ = "blocked_ips"

    # ── Primary fields ─────────────────────────────────────────────────────────
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)

    # ── Block metadata ─────────────────────────────────────────────────────────
    reason = db.Column(db.String(256), nullable=False)
    risk_score = db.Column(db.Integer, default=0, nullable=False)

    # ── Timestamps ─────────────────────────────────────────────────────────────
    blocked_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    expires_at = db.Column(
        db.DateTime(timezone=True), nullable=False, index=True
    )

    # ── Status ─────────────────────────────────────────────────────────────────
    # True  → block is currently enforced
    # False → manually deactivated by an admin or expired
    active = db.Column(db.Boolean, default=True, nullable=False, index=True)

    # Optional admin note (e.g., reason for manual unblock)
    admin_note = db.Column(db.Text, nullable=True)

    # ── Computed helpers ───────────────────────────────────────────────────────
    @property
    def is_expired(self) -> bool:
        """Return True if the block's expiry time has passed."""
        if not self.expires_at:
            return False
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= exp

    @property
    def is_currently_blocked(self) -> bool:
        """Return True only if the block is active AND not yet expired."""
        return self.active and not self.is_expired


    def deactivate(self, note: str = "") -> None:
        """Manually deactivate this block (admin action)."""
        self.active = False
        if note:
            self.admin_note = note

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "reason": self.reason,
            "risk_score": self.risk_score,
            "blocked_at": self.blocked_at.isoformat() if self.blocked_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "active": self.active,
            "is_expired": self.is_expired,
            "is_currently_blocked": self.is_currently_blocked,
            "admin_note": self.admin_note,
        }

    def __repr__(self) -> str:
        return (
            f"<BlockedIP id={self.id} ip={self.ip_address!r} "
            f"active={self.active} expired={self.is_expired}>"
        )
