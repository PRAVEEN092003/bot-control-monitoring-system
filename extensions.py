"""
extensions.py — Flask extension singletons.

All extensions are instantiated here without an app object (application
factory pattern).  They are initialised with the real app inside
create_app() in app.py.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ── Database ORM ───────────────────────────────────────────────────────────────
db = SQLAlchemy()

# ── Authentication ─────────────────────────────────────────────────────────────
login_manager = LoginManager()
login_manager.login_view = "auth.login"           # redirect target for @login_required
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"
login_manager.session_protection = "strong"       # invalidate session on IP change

# ── CSRF Protection ────────────────────────────────────────────────────────────
csrf = CSRFProtect()

# ── Rate Limiter ───────────────────────────────────────────────────────────────
# key_func defaults to the client's remote address.
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    headers_enabled=True,
)
