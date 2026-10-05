"""
routes/auth.py — Authentication blueprint.

Endpoints
---------
GET/POST  /auth/register   — New user registration
GET/POST  /auth/login      — User login
GET       /auth/logout     — Logout (login required)

Security measures
-----------------
- CSRF protection on all forms (via Flask-WTF FlaskForm)
- Server-side input validation (username, email, password strength)
- Bcrypt password hashing (delegated to User.set_password)
- last_login timestamp updated on successful login
- Failed-login counter tracked on User model
- All events logged to ActivityLog via monitoring service
- Inactive users are blocked at login
"""

import logging
from urllib.parse import urljoin, urlparse

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy.exc import IntegrityError

from extensions import db, limiter
from forms.auth_forms import LoginForm, RegistrationForm
from models.activity import ActivityStatus, EventType
from models.user import User
from services.captcha_service import (
    clear_captcha_session,
    create_captcha_session,
    generate_captcha_base64,
    is_captcha_expired,
    verify_captcha,
)
from services.monitoring import (
    log_event,
    log_login_failure,
    log_login_success,
    log_logout,
    log_register_failure,
    log_register_success,
)

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def _is_safe_url(target: str | None) -> bool:
    """Ensure redirect targets are safe relative paths or belong to the same host."""
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


# ── Registration ───────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute; 20 per hour")
def register():

    """Handle new user account creation."""
    if current_user.is_authenticated:
        return redirect(url_for("user.dashboard"))

    form = RegistrationForm()

    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip().lower()
        password = form.password.data

        # ── Uniqueness checks ──────────────────────────────────────────────────
        if User.query.filter_by(username=username).first():
            flash("Username is already taken. Please choose another.", "danger")
            log_register_failure(username, "username already exists")
            return render_template("register.html", form=form)

        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "danger")
            log_register_failure(username, "email already exists")
            return render_template("register.html", form=form)

        # ── Create user ────────────────────────────────────────────────────────
        try:
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            log_register_success(user.id, username)
            logger.info(f"New user registered: {username} ({email})")

            flash(
                "Account created successfully! You can now log in.",
                "success",
            )
            return redirect(url_for("auth.login"))

        except IntegrityError:
            db.session.rollback()
            flash("Registration failed due to a database error. Please try again.", "danger")
            log_register_failure(username, "database integrity error")
            logger.error(f"IntegrityError during registration for {username}")
            return render_template("register.html", form=form)

        except Exception as exc:
            db.session.rollback()
            flash("An unexpected error occurred. Please try again.", "danger")
            log_register_failure(username, f"unexpected error: {exc}")
            logger.error(f"Registration error for {username}: {exc}", exc_info=True)
            return render_template("register.html", form=form)

    # GET or failed validation
    return render_template("register.html", form=form)


# ── Login ──────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute; 30 per hour")
def login():

    """Authenticate an existing user and establish a session."""
    if current_user.is_authenticated:
        return redirect(url_for("user.dashboard"))

    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        password = form.password.data
        remember = form.remember_me.data

        user = User.query.filter_by(email=email).first()

        # Check if CAPTCHA is required for this login attempt
        captcha_required = bool(
            (user and (user.failed_login_count or 0) >= 2)
            or session.get("require_captcha")
        )

        if captcha_required:
            user_input = form.captcha_input.data if form.captcha_input else request.form.get("captcha_input", "")
            user_id = user.id if user else None

            is_valid, captcha_msg = verify_captcha(
                user_input=user_input,
                user_id=user_id,
            )

            if not is_valid:
                session["require_captcha"] = True
                _, new_image = create_captcha_session()
                flash(captcha_msg, "danger")
                return render_template(
                    "login.html",
                    form=form,
                    require_captcha=True,
                    captcha_image=new_image,
                )

        # ── Credential check ───────────────────────────────────────────────────
        if user is None or not user.check_password(password):
            # Deliberately vague message (don't reveal which field is wrong)
            flash("Invalid email or password.", "danger")
            log_login_failure(email, "invalid credentials", user_id=user.id if user else None)

            if user:
                user.record_failed_login()
                db.session.commit()

                if (user.failed_login_count or 0) >= 2:
                    session["require_captcha"] = True
                    _, new_image = create_captcha_session()
                    return render_template(
                        "login.html",
                        form=form,
                        require_captcha=True,
                        captcha_image=new_image,
                    )

            if session.get("require_captcha"):
                _, new_image = create_captcha_session()
                return render_template(
                    "login.html",
                    form=form,
                    require_captcha=True,
                    captcha_image=new_image,
                )

            return render_template("login.html", form=form, require_captcha=False)

        # ── Account status check ───────────────────────────────────────────────
        if not user.is_active:
            flash("Your account has been deactivated. Please contact support.", "danger")
            log_event(
                event_type=EventType.LOGIN_FAILURE,
                description=f"Login attempt on deactivated account: {email}.",
                status=ActivityStatus.BLOCKED,
                risk_score=10,
            )
            return render_template("login.html", form=form)

        # ── Successful login ───────────────────────────────────────────────────
        login_user(user, remember=remember)
        user.record_login()
        db.session.commit()

        # Reset CAPTCHA requirement on successful login
        session.pop("require_captcha", None)
        clear_captcha_session()

        log_login_success(user.id, user.username)
        logger.info(f"User logged in: {user.username} from {request.remote_addr}")

        flash(f"Welcome back, {user.username}!", "success")

        # Safe redirect — prevent open redirects
        next_page = request.args.get("next")
        if next_page and _is_safe_url(next_page):
            return redirect(next_page)
        return redirect(url_for("user.dashboard"))

    # GET or failed validation
    require_captcha = bool(session.get("require_captcha"))
    captcha_image = None
    if require_captcha:
        if "captcha_text" not in session or is_captcha_expired():
            _, captcha_image = create_captcha_session()
        else:
            captcha_image = generate_captcha_base64(session["captcha_text"])

    return render_template(
        "login.html",
        form=form,
        require_captcha=require_captcha,
        captcha_image=captcha_image,
    )



# ── Logout ─────────────────────────────────────────────────────────────────────

@auth_bp.route("/logout")
@login_required
def logout():
    """Terminate the current user session."""
    username = current_user.username
    user_id = current_user.id
    logout_user()
    log_logout(user_id, username)
    logger.info(f"User logged out: {username}")
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("auth.login"))


# ── Phase 1 health-check (preserved) ──────────────────────────────────────────

@auth_bp.route("/ping")
def ping():
    """Health-check endpoint (Phase 1 compatibility)."""
    return {"status": "auth blueprint registered", "phase": 2}
