"""
app.py — Application entry-point and factory.

Uses the application factory pattern so the same create_app() call
can be used for development, production, and testing without importing
a global app object.
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify, redirect, render_template, url_for

from config import get_config
from extensions import csrf, db, limiter, login_manager


def create_app(config_class=None) -> Flask:
    """
    Application factory.

    Parameters
    ----------
    config_class : type, optional
        A configuration class.  Falls back to the class selected by
        FLASK_ENV when omitted.
    """
    app = Flask(__name__)

    # ── Load configuration ─────────────────────────────────────────────────────
    cfg = config_class or get_config()
    app.config.from_object(cfg)

    # ── Initialise extensions ──────────────────────────────────────────────────
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # ── Configure logging ──────────────────────────────────────────────────────
    _configure_logging(app)

    # ── Register Flask-Login user loader ───────────────────────────────────────
    _register_user_loader()

    # ── Register IP block enforcement ──────────────────────────────────────────
    _register_ip_block_check(app)

    # ── Register blueprints ────────────────────────────────────────────────────
    _register_blueprints(app)

    # ── Register security headers ──────────────────────────────────────────────
    _register_security_headers(app)

    # ── Register error handlers ────────────────────────────────────────────────
    _register_error_handlers(app)


    # ── Create database tables & seed admin ───────────────────────────────────
    with app.app_context():
        _init_database(app)

    # ── Register index route ─────────────────────────────────────────────────────
    @app.route("/")
    def index():
        from flask_login import current_user
        if current_user.is_authenticated:
            return redirect(url_for("user.dashboard"))
        return redirect(url_for("auth.login"))

    app.logger.info(
        "Bot Control and Monitoring System started "
        f"[env={os.environ.get('FLASK_ENV', 'development')}]"
    )
    return app


# ── Private helpers ────────────────────────────────────────────────────────────

def _configure_logging(app: Flask) -> None:
    """Set up console + rotating-file logging."""
    log_level = getattr(logging, app.config.get("LOG_LEVEL", "INFO"), logging.INFO)

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)

    # Rotating file handler (5 MB × 3 backups)
    os.makedirs("logs", exist_ok=True)
    file_handler = RotatingFileHandler(
        "logs/app.log", maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(log_level)

    # Attach to Flask root logger
    app.logger.setLevel(log_level)
    if not app.logger.handlers:
        app.logger.addHandler(console_handler)
        app.logger.addHandler(file_handler)


def _register_user_loader() -> None:
    """Tell Flask-Login how to reload a user from its session ID."""

    @login_manager.user_loader
    def load_user(user_id: str):
        from models.user import User
        return db.session.get(User, int(user_id))


def _register_ip_block_check(app: Flask) -> None:
    """Enforce temporary IP blocking before each request."""

    @app.before_request
    def check_ip_block():
        from flask import request
        # Skip static assets
        if request.path.startswith("/static/"):
            return None

        from services.monitoring import _get_client_ip
        from services.ip_blocker import is_ip_blocked

        try:
            client_ip = _get_client_ip()
            blocked, block_record = is_ip_blocked(client_ip)
            if blocked and block_record:
                expires_str = block_record.expires_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                return (
                    jsonify(
                        error="Forbidden",
                        message=(
                            f"Access denied: Your IP address ({client_ip}) is temporarily blocked "
                            f"until {expires_str}. Reason: {block_record.reason}"
                        ),
                        blocked=True,
                        ip_address=client_ip,
                        expires_at=block_record.expires_at.isoformat(),
                    ),
                    403,
                )
        except Exception as exc:
            app.logger.error(f"Error during IP block check: {exc}")

        return None


def _register_blueprints(app: Flask) -> None:
    """Import and register all route blueprints."""
    from routes.auth import auth_bp
    from routes.user import user_bp
    from routes.captcha import captcha_bp
    from routes.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(captcha_bp)
    app.register_blueprint(admin_bp)

    app.logger.debug("All blueprints registered.")


def _register_security_headers(app: Flask) -> None:
    """Inject standard cybersecurity HTTP response headers."""

    @app.after_request
    def add_security_headers(response):
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Clickjacking defense: allow framing only from the same origin
        response.headers["X-Frame-Options"] = "SAMEORIGIN"

        # Cross-Site Scripting filter (for legacy browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer privacy policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Restrict unnecessary browser permissions
        response.headers["Permissions-Policy"] = (
            "geolocation=(), camera=(), microphone=(), payment=()"
        )

        # Content Security Policy (CSP)
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net data:; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'self';"
        )
        response.headers["Content-Security-Policy"] = csp_policy

        # HSTS only when running over HTTPS / secure cookies
        if app.config.get("SESSION_COOKIE_SECURE", False):
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        return response


def _register_error_handlers(app: Flask) -> None:
    """Register custom error pages / JSON responses without leaking internal stack traces."""

    @app.errorhandler(400)
    def bad_request(e):
        return jsonify(error="Bad Request", message="Invalid or malformed request parameters."), 400

    @app.errorhandler(401)
    def unauthorised(e):
        return jsonify(error="Unauthorised", message="Authentication required."), 401

    @app.errorhandler(403)
    def forbidden(e):
        return jsonify(error="Forbidden", message="Access denied."), 403

    @app.errorhandler(404)
    def not_found(e):
        return jsonify(error="Not Found", message="The requested resource was not found."), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify(error="Method Not Allowed", message="HTTP method not allowed for this endpoint."), 405

    @app.errorhandler(429)
    def too_many_requests(e):
        from flask import request
        from services.monitoring import log_event
        from models.activity import ActivityStatus, EventType

        log_event(
            event_type=EventType.RATE_LIMIT_EXCEEDED,
            description=f"Rate limit exceeded on endpoint '{request.path}'.",
            risk_score=30,
            status=ActivityStatus.BLOCKED,
        )
        return (
            jsonify(
                error="Too Many Requests",
                message="Rate limit exceeded. Please wait before retrying.",
            ),
            429,
        )

    @app.errorhandler(500)
    def internal_error(e):
        app.logger.error(f"Internal Server Error: {e}", exc_info=True)
        db.session.rollback()
        return jsonify(
            error="Internal Server Error",
            message="An unexpected error occurred. Please try again later.",
        ), 500


def _init_database(app: Flask) -> None:
    """Create all tables and optionally seed the admin account."""
    # Import all models so SQLAlchemy knows about them before create_all()
    import models  # noqa: F401 — side-effect import

    db.create_all()
    app.logger.info("Database tables verified / created.")

    _seed_admin(app)


def _seed_admin(app: Flask) -> None:
    """
    Create the initial admin account from environment variables.

    This runs only when:
    - ADMIN_EMAIL and ADMIN_PASSWORD are set in the environment, AND
    - No admin account exists yet.

    The password is bcrypt-hashed before storage.
    """
    from models.user import User

    admin_username = app.config.get("ADMIN_USERNAME", "").strip()
    admin_email = app.config.get("ADMIN_EMAIL", "").strip()
    admin_password = app.config.get("ADMIN_PASSWORD", "").strip()

    if not (admin_email and admin_password):
        app.logger.warning(
            "ADMIN_EMAIL / ADMIN_PASSWORD not set — skipping admin seed.  "
            "Set them in your .env file to create the initial admin account."
        )
        return

    existing = User.query.filter(
        (User.email == admin_email) | (User.username == (admin_username or "admin"))
    ).first()
    if existing:
        app.logger.info(f"Admin account already exists: {existing.email}")
        return


    admin = User(
        username=admin_username or "admin",
        email=admin_email,
        is_admin=True,
    )
    admin.set_password(admin_password)
    db.session.add(admin)
    db.session.commit()
    app.logger.info(f"Admin account seeded: {admin_email}")


# ── Entrypoint ─────────────────────────────────────────────────────────────────

app = create_app()

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=app.config.get("DEBUG", True),
    )
