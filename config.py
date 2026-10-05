"""
config.py — Centralised application configuration.

All settings are loaded from environment variables (via python-dotenv).
No secrets are hardcoded here.
"""

import os
from dotenv import load_dotenv

# Load .env file if it exists (development convenience)
load_dotenv()


class BaseConfig:
    """Shared settings for all environments."""

    # ── Flask core ─────────────────────────────────────────────────────────────
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "dev-secret-CHANGE-ME")
    WTF_CSRF_ENABLED: bool = True
    WTF_CSRF_TIME_LIMIT: int = 3600  # 1 hour

    # ── Database ───────────────────────────────────────────────────────────────
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_URL", "sqlite:///bot_monitor.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ECHO: bool = False  # Set True to log all SQL in dev

    # ── Session security ───────────────────────────────────────────────────────
    SESSION_COOKIE_SECURE: bool = (
        os.environ.get("SESSION_COOKIE_SECURE", "False").lower() == "true"
    )
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = os.environ.get(
        "SESSION_COOKIE_SAMESITE", "Lax"
    )
    PERMANENT_SESSION_LIFETIME: int = 3600  # seconds (1 hour)
    REMEMBER_COOKIE_HTTPONLY: bool = True
    REMEMBER_COOKIE_SAMESITE: str = "Lax"
    REMEMBER_COOKIE_SECURE: bool = (
        os.environ.get("SESSION_COOKIE_SECURE", "False").lower() == "true"
    )

    # ── Rate limiting ──────────────────────────────────────────────────────────
    RATELIMIT_STORAGE_URI: str = os.environ.get(
        "RATELIMIT_STORAGE_URI", "memory://"
    )
    RATELIMIT_HEADERS_ENABLED: bool = True
    RATELIMIT_DEFAULT: str = "200 per day;50 per hour"

    # ── CAPTCHA settings ───────────────────────────────────────────────────────
    CAPTCHA_LENGTH: int = int(os.environ.get("CAPTCHA_LENGTH", "6"))
    CAPTCHA_EXPIRY_SECONDS: int = int(
        os.environ.get("CAPTCHA_EXPIRY_SECONDS", "120")
    )

    # ── Risk score thresholds ──────────────────────────────────────────────────
    RISK_SUSPICIOUS_THRESHOLD: int = int(
        os.environ.get("RISK_SUSPICIOUS_THRESHOLD", "31")
    )
    RISK_HIGH_THRESHOLD: int = int(
        os.environ.get("RISK_HIGH_THRESHOLD", "61")
    )

    # ── Temporary IP block ─────────────────────────────────────────────────────
    IP_BLOCK_DURATION_MINUTES: int = int(
        os.environ.get("IP_BLOCK_DURATION_MINUTES", "30")
    )

    # ── Admin bootstrap ────────────────────────────────────────────────────────
    ADMIN_USERNAME: str = os.environ.get("ADMIN_USERNAME", "")
    ADMIN_EMAIL: str = os.environ.get("ADMIN_EMAIL", "")
    ADMIN_PASSWORD: str = os.environ.get("ADMIN_PASSWORD", "")

    # ── Logging ────────────────────────────────────────────────────────────────
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")


class DevelopmentConfig(BaseConfig):
    """Development-specific overrides."""

    DEBUG: bool = True
    SQLALCHEMY_ECHO: bool = False  # Flip to True when debugging SQL
    SESSION_COOKIE_SECURE: bool = False  # HTTP is fine locally


class ProductionConfig(BaseConfig):
    """Production-specific overrides."""

    DEBUG: bool = False
    TESTING: bool = False
    SESSION_COOKIE_SECURE: bool = True  # Must use HTTPS in production
    REMEMBER_COOKIE_SECURE: bool = True


class TestingConfig(BaseConfig):
    """Test-suite configuration."""

    TESTING: bool = True
    DEBUG: bool = True
    WTF_CSRF_ENABLED: bool = False  # Disable CSRF in tests
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///:memory:"
    RATELIMIT_ENABLED: bool = False  # Disable rate limits in tests


# ── Config registry ────────────────────────────────────────────────────────────
config_by_name: dict = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}


def get_config() -> type:
    """Return the active configuration class based on FLASK_ENV."""
    env = os.environ.get("FLASK_ENV", "development").lower()
    return config_by_name.get(env, DevelopmentConfig)
