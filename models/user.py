"""
models/user.py — User account model.

Stores credentials, roles, and login-tracking metadata.
Passwords are NEVER stored in plaintext — bcrypt hashes only.
"""

from datetime import datetime, timezone
from flask_login import UserMixin
from extensions import db
import bcrypt


class User(UserMixin, db.Model):
    """Application user.  Supports both regular users and administrators."""

    __tablename__ = "users"

    # ── Primary fields ─────────────────────────────────────────────────────────
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(
        db.String(64), unique=True, nullable=False, index=True
    )
    email = db.Column(
        db.String(120), unique=True, nullable=False, index=True
    )
    password_hash = db.Column(db.String(128), nullable=False)

    # ── Role ───────────────────────────────────────────────────────────────────
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # ── Timestamps ─────────────────────────────────────────────────────────────
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_login = db.Column(db.DateTime(timezone=True), nullable=True)

    # ── Login-attempt tracking ─────────────────────────────────────────────────
    failed_login_count = db.Column(db.Integer, default=0, nullable=False)
    last_failed_login = db.Column(db.DateTime(timezone=True), nullable=True)

    # ── Relationships ──────────────────────────────────────────────────────────
    activity_logs = db.relationship(
        "ActivityLog", backref="user", lazy="dynamic", cascade="all, delete-orphan"
    )
    captcha_attempts = db.relationship(
        "CaptchaAttempt", backref="user", lazy="dynamic", cascade="all, delete-orphan"
    )

    # ── Password helpers ───────────────────────────────────────────────────────
    def set_password(self, plaintext: str) -> None:
        """Hash *plaintext* with bcrypt and store the result."""
        if not plaintext:
            raise ValueError("Password must not be empty.")
        hashed = bcrypt.hashpw(plaintext.encode("utf-8"), bcrypt.gensalt(rounds=12))
        self.password_hash = hashed.decode("utf-8")

    def check_password(self, plaintext: str) -> bool:
        """Return True if *plaintext* matches the stored bcrypt hash."""
        if not plaintext or not self.password_hash:
            return False
        return bcrypt.checkpw(
            plaintext.encode("utf-8"), self.password_hash.encode("utf-8")
        )

    # ── Flask-Login integration ────────────────────────────────────────────────
    def get_id(self) -> str:
        """Flask-Login requires a string identifier."""
        return str(self.id)

    # ── Helpers ────────────────────────────────────────────────────────────────
    def record_login(self) -> None:
        """Update last_login timestamp and reset failed-login counter."""
        self.last_login = datetime.now(timezone.utc)
        self.failed_login_count = 0
        self.last_failed_login = None

    def record_failed_login(self) -> None:
        """Increment failed-login counter and timestamp."""
        self.failed_login_count = (self.failed_login_count or 0) + 1
        self.last_failed_login = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        """Serialise to a safe dictionary (no password hash exposed)."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "is_admin": self.is_admin,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "failed_login_count": self.failed_login_count,
        }

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r} admin={self.is_admin}>"
