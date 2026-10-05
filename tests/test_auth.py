"""
tests/test_auth.py — Authentication tests (Phase 2).

Covers:
- Registration success / failure scenarios
- Login success / failure scenarios
- Logout
- Password hashing (preserved from Phase 1)
- CSRF protection
- Protected routes redirect unauthenticated users
- last_login is updated after successful login
- Failed-login counter increments on failure
- ActivityLog entries are created for all events
"""

import pytest
from models.user import User
from models.activity import ActivityLog, EventType


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

REG_URL    = "/auth/register"
LOGIN_URL  = "/auth/login"
LOGOUT_URL = "/auth/logout"
DASH_URL   = "/user/dashboard"

VALID_REG = {
    "username": "testuser",
    "email": "testuser@example.com",
    "password": "Secure@Pass1",
    "confirm_password": "Secure@Pass1",
}

VALID_LOGIN = {
    "email": "testuser@example.com",
    "password": "Secure@Pass1",
}


def _register(client, data=None):
    """POST to the register endpoint (CSRF disabled in TestingConfig)."""
    payload = {**VALID_REG, **(data or {})}
    return client.post(REG_URL, data=payload, follow_redirects=True)


def _login(client, data=None):
    """POST to the login endpoint."""
    payload = {**VALID_LOGIN, **(data or {})}
    return client.post(LOGIN_URL, data=payload, follow_redirects=True)


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 — User model (preserved)
# ─────────────────────────────────────────────────────────────────────────────

class TestUserModel:

    def test_set_and_check_password(self, db):
        user = User(username="t1", email="t1@example.com")
        user.set_password("MySecurePass123!")
        assert user.check_password("MySecurePass123!") is True

    def test_wrong_password_rejected(self, db):
        user = User(username="t2", email="t2@example.com")
        user.set_password("CorrectPassword!")
        assert user.check_password("WrongPassword!") is False

    def test_password_not_stored_in_plaintext(self, db):
        plaintext = "PlaintextSecret99!"
        user = User(username="t3", email="t3@example.com")
        user.set_password(plaintext)
        assert user.password_hash != plaintext

    def test_empty_password_raises(self, db):
        user = User(username="t4", email="t4@example.com")
        with pytest.raises(ValueError):
            user.set_password("")

    def test_user_to_dict_excludes_hash(self, db):
        user = User(username="t5", email="t5@example.com")
        user.set_password("SomePassword!")
        d = user.to_dict()
        assert "password_hash" not in d
        assert "password" not in d

    def test_user_get_id_returns_string(self, db):
        user = User(username="t6", email="t6@example.com")
        user.set_password("Pass@Word1")
        db.session.add(user)
        db.session.commit()
        assert isinstance(user.get_id(), str)


# ─────────────────────────────────────────────────────────────────────────────
# Registration
# ─────────────────────────────────────────────────────────────────────────────

class TestRegistration:

    def test_register_page_loads(self, client, db):
        """GET /auth/register returns 200."""
        r = client.get(REG_URL)
        assert r.status_code == 200
        assert b"Create Account" in r.data

    def test_successful_registration(self, client, db):
        """Valid registration creates a user and redirects to login."""
        r = _register(client)
        assert r.status_code == 200
        assert b"Sign In" in r.data or b"Account created" in r.data

        user = User.query.filter_by(email=VALID_REG["email"]).first()
        assert user is not None
        assert user.username == VALID_REG["username"]

    def test_password_is_hashed_on_registration(self, client, db):
        """Password stored as bcrypt hash, not plaintext."""
        _register(client)
        user = User.query.filter_by(email=VALID_REG["email"]).first()
        assert user is not None
        assert user.password_hash != VALID_REG["password"]
        assert user.check_password(VALID_REG["password"]) is True

    def test_duplicate_username_rejected(self, client, db):
        """Second registration with same username fails."""
        _register(client)
        r = _register(client, {"email": "other@example.com"})
        assert b"already taken" in r.data

    def test_duplicate_email_rejected(self, client, db):
        """Second registration with same email fails."""
        _register(client)
        r = _register(client, {"username": "otherusername"})
        assert b"already exists" in r.data

    def test_weak_password_rejected(self, client, db):
        """Password without special character is rejected."""
        r = _register(client, {"password": "weakpassword", "confirm_password": "weakpassword"})
        assert b"Create Account" in r.data

    def test_mismatched_passwords_rejected(self, client, db):
        """Passwords that do not match are rejected."""
        r = _register(client, {"confirm_password": "DifferentPass@1"})
        assert b"Create Account" in r.data

    def test_blank_username_rejected(self, client, db):
        """Empty username is rejected by form validation."""
        r = _register(client, {"username": ""})
        assert b"Create Account" in r.data

    def test_invalid_email_rejected(self, client, db):
        """Malformed email is rejected."""
        r = _register(client, {"email": "not-an-email"})
        assert b"Create Account" in r.data

    def test_short_username_rejected(self, client, db):
        """Username shorter than 3 chars is rejected."""
        r = _register(client, {"username": "ab"})
        assert b"Create Account" in r.data

    def test_register_logs_activity(self, client, db):
        """Successful registration creates a REGISTER_SUCCESS ActivityLog."""
        _register(client)
        log = ActivityLog.query.filter_by(
            event_type=EventType.REGISTER_SUCCESS
        ).first()
        assert log is not None

    def test_authenticated_user_redirected_from_register(self, client, db):
        """Already-logged-in user is redirected away from register."""
        _register(client)
        _login(client)
        r = client.get(REG_URL, follow_redirects=True)
        assert b"My Dashboard" in r.data


# ─────────────────────────────────────────────────────────────────────────────
# Login
# ─────────────────────────────────────────────────────────────────────────────

class TestLogin:

    def test_login_page_loads(self, client, db):
        """GET /auth/login returns 200."""
        r = client.get(LOGIN_URL)
        assert r.status_code == 200
        assert b"Sign In" in r.data

    def test_successful_login(self, client, db):
        """Valid credentials log the user in and redirect to dashboard."""
        _register(client)
        r = _login(client)
        assert r.status_code == 200
        assert b"My Dashboard" in r.data

    def test_last_login_updated_after_login(self, client, db):
        """last_login timestamp is set after successful login."""
        _register(client)
        user = User.query.filter_by(email=VALID_REG["email"]).first()
        assert user is not None
        assert user.last_login is None  # not set before first login

        _login(client)
        db.session.expire(user)
        user = User.query.filter_by(email=VALID_REG["email"]).first()
        assert user.last_login is not None

    def test_failed_login_counter_increments(self, client, db):
        """failed_login_count increases on bad password."""
        _register(client)
        user = User.query.filter_by(email=VALID_REG["email"]).first()
        assert user is not None
        assert user.failed_login_count == 0

        _login(client, {"password": "wrongpassword"})
        db.session.expire(user)
        user = User.query.filter_by(email=VALID_REG["email"]).first()
        assert user.failed_login_count == 1

    def test_failed_login_counter_resets_on_success(self, client, db):
        """failed_login_count resets to 0 after successful login."""
        _register(client)
        _login(client, {"password": "wrongpassword"})  # bump counter

        user = User.query.filter_by(email=VALID_REG["email"]).first()
        assert user is not None
        db.session.expire(user)
        user = User.query.filter_by(email=VALID_REG["email"]).first()
        assert user.failed_login_count == 1

        _login(client)  # correct password
        db.session.expire(user)
        user = User.query.filter_by(email=VALID_REG["email"]).first()
        assert user.failed_login_count == 0

    def test_wrong_password_rejected(self, client, db):
        """Incorrect password shows error, stays on login page."""
        _register(client)
        # Logout first to clear any session state
        client.get(LOGOUT_URL)
        r = _login(client, {"password": "WrongPass@1"})
        assert b"Invalid email or password" in r.data

    def test_nonexistent_email_rejected(self, client, db):
        """Unknown email shows generic error (no user-enum leak)."""
        r = _login(client, {"email": "nobody@example.com", "password": "SomePass@1"})
        assert b"Invalid email or password" in r.data

    def test_login_logs_success_activity(self, client, db):
        """Successful login creates a LOGIN_SUCCESS ActivityLog."""
        _register(client)
        _login(client)
        log = ActivityLog.query.filter_by(
            event_type=EventType.LOGIN_SUCCESS
        ).first()
        assert log is not None

    def test_login_logs_failure_activity(self, client, db):
        """Failed login creates a LOGIN_FAILURE ActivityLog."""
        _register(client)
        client.get(LOGOUT_URL)
        _login(client, {"password": "BadPassword@9"})
        log = ActivityLog.query.filter_by(
            event_type=EventType.LOGIN_FAILURE
        ).first()
        assert log is not None

    def test_authenticated_user_redirected_from_login(self, client, db):
        """Already-logged-in user is redirected away from login."""
        _register(client)
        _login(client)
        r = client.get(LOGIN_URL, follow_redirects=True)
        assert b"My Dashboard" in r.data

    def test_blank_email_rejected(self, client, db):
        """Empty email field fails form validation."""
        r = client.post(LOGIN_URL, data={"email": "", "password": "abc"},
                        follow_redirects=True)
        assert b"Sign In" in r.data

    def test_blank_password_rejected(self, client, db):
        """Empty password field fails form validation."""
        r = client.post(LOGIN_URL,
                        data={"email": "x@example.com", "password": ""},
                        follow_redirects=True)
        assert b"Sign In" in r.data


# ─────────────────────────────────────────────────────────────────────────────
# Logout
# ─────────────────────────────────────────────────────────────────────────────

class TestLogout:

    def test_logout_requires_login(self, client, db):
        """Unauthenticated GET /auth/logout redirects to login."""
        r = client.get(LOGOUT_URL, follow_redirects=True)
        assert b"Sign In" in r.data

    def test_logout_redirects_to_login(self, client, db):
        """After logout, user lands on the login page."""
        _register(client)
        _login(client)
        r = client.get(LOGOUT_URL, follow_redirects=True)
        assert b"Sign In" in r.data

    def test_logout_ends_session(self, client, db):
        """Dashboard is inaccessible after logout."""
        _register(client)
        _login(client)
        client.get(LOGOUT_URL)
        r = client.get(DASH_URL, follow_redirects=True)
        assert b"Sign In" in r.data

    def test_logout_logs_activity(self, client, db):
        """Logout creates a LOGOUT ActivityLog."""
        _register(client)
        _login(client)
        client.get(LOGOUT_URL)
        log = ActivityLog.query.filter_by(event_type=EventType.LOGOUT).first()
        assert log is not None


# ─────────────────────────────────────────────────────────────────────────────
# Protected routes
# ─────────────────────────────────────────────────────────────────────────────

class TestProtectedRoutes:

    def test_dashboard_requires_login(self, client, db):
        """Unauthenticated access to dashboard redirects to login."""
        r = client.get(DASH_URL, follow_redirects=True)
        assert r.status_code == 200
        assert b"Sign In" in r.data

    def test_dashboard_accessible_when_logged_in(self, client, db):
        """Authenticated user can access their dashboard."""
        _register(client)
        _login(client)
        r = client.get(DASH_URL)
        assert r.status_code == 200
        assert b"My Dashboard" in r.data

    def test_root_redirects_anon_to_login(self, client, db):
        """GET / redirects anonymous users to login."""
        r = client.get("/", follow_redirects=True)
        assert b"Sign In" in r.data

    def test_root_redirects_auth_to_dashboard(self, client, db):
        """GET / redirects authenticated users to their dashboard."""
        _register(client)
        _login(client)
        r = client.get("/", follow_redirects=True)
        assert b"My Dashboard" in r.data


# ─────────────────────────────────────────────────────────────────────────────
# CSRF protection
# ─────────────────────────────────────────────────────────────────────────────

class TestCSRFProtection:
    """
    CSRF is disabled in TestingConfig (WTF_CSRF_ENABLED = False) so the
    main functional tests can POST without tokens.

    These tests verify that FlaskForm provides hidden_tag() and that a
    CSRF-enabled app instance renders csrf_token in the HTML.
    """

    def test_login_form_has_hidden_tag(self):
        """LoginForm (FlaskForm) must expose the hidden_tag() method."""
        from forms.auth_forms import LoginForm
        assert hasattr(LoginForm, "hidden_tag")

    def test_register_form_has_hidden_tag(self):
        """RegistrationForm (FlaskForm) must expose the hidden_tag() method."""
        from forms.auth_forms import RegistrationForm
        assert hasattr(RegistrationForm, "hidden_tag")

    def test_login_csrf_token_in_html_with_csrf_enabled(self, app):
        """Login page renders a csrf_token input when CSRF is enabled."""
        from config import DevelopmentConfig
        from app import create_app as _create_app

        class CSRFConfig(DevelopmentConfig):
            TESTING = True
            WTF_CSRF_ENABLED = True
            SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
            SECRET_KEY = "csrf-test-secret-32chars-exactly!"
            RATELIMIT_ENABLED = False

        csrf_app = _create_app(CSRFConfig)
        with csrf_app.app_context():
            from extensions import db as _db
            _db.create_all()
            with csrf_app.test_client() as c:
                r = c.get("/auth/login")
                assert b"csrf_token" in r.data

    def test_register_csrf_token_in_html_with_csrf_enabled(self, app):
        """Register page renders a csrf_token input when CSRF is enabled."""
        from config import DevelopmentConfig
        from app import create_app as _create_app

        class CSRFConfig(DevelopmentConfig):
            TESTING = True
            WTF_CSRF_ENABLED = True
            SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
            SECRET_KEY = "csrf-test-secret-32chars-exactly!"
            RATELIMIT_ENABLED = False

        csrf_app = _create_app(CSRFConfig)
        with csrf_app.app_context():
            from extensions import db as _db
            _db.create_all()
            with csrf_app.test_client() as c:
                r = c.get("/auth/register")
                assert b"csrf_token" in r.data


# ─────────────────────────────────────────────────────────────────────────────
# Login to CAPTCHA Integration
# ─────────────────────────────────────────────────────────────────────────────

class TestLoginCaptchaIntegration:
    """Tests for the 2-failed-attempts CAPTCHA integration on login."""

    def test_normal_first_login_does_not_require_captcha(self, client, db):
        """Normal first login does NOT display or require CAPTCHA."""
        _register(client)
        r = client.get(LOGIN_URL)
        assert b"Verification Image" not in r.data
        assert b"captcha_input" not in r.data

        r = _login(client)
        assert r.status_code == 200
        assert b"My Dashboard" in r.data

    def test_one_failed_login_does_not_trigger_captcha(self, client, db):
        """After 1 failed attempt, CAPTCHA is not triggered yet."""
        _register(client)
        client.get(LOGOUT_URL)

        r = _login(client, {"password": "WrongPassword@1"})
        assert b"Invalid email or password" in r.data
        assert b"Verification Image" not in r.data

        user = User.query.filter_by(email=VALID_LOGIN["email"]).first()
        assert user.failed_login_count == 1

    def test_two_failed_logins_triggers_captcha_challenge(self, client, db):
        """After 2 consecutive failed attempts, CAPTCHA challenge is displayed."""
        _register(client)
        client.get(LOGOUT_URL)

        # Attempt 1
        _login(client, {"password": "WrongPassword@1"})
        # Attempt 2
        r = _login(client, {"password": "WrongPassword@2"})

        assert r.status_code == 200
        assert b"Verification Image" in r.data
        assert b"captcha_input" in r.data

        user = User.query.filter_by(email=VALID_LOGIN["email"]).first()
        assert user.failed_login_count == 2

    def test_wrong_captcha_rejects_login_and_logs_failure(self, client, db):
        """Wrong CAPTCHA answer rejects login and logs CAPTCHA_FAILURE without checking password."""
        _register(client)
        client.get(LOGOUT_URL)

        # 2 failures
        _login(client, {"password": "WrongPassword@1"})
        _login(client, {"password": "WrongPassword@2"})

        # Attempt 3 with WRONG CAPTCHA and correct password
        r = client.post(
            LOGIN_URL,
            data={
                "email": VALID_LOGIN["email"],
                "password": VALID_LOGIN["password"],
                "captcha_input": "WRONGCODE",
            },
            follow_redirects=True,
        )

        assert r.status_code == 200
        assert b"Incorrect CAPTCHA answer" in r.data or b"CAPTCHA" in r.data
        assert b"My Dashboard" not in r.data

        # Verify CAPTCHA_FAILURE logged
        captcha_fail_log = ActivityLog.query.filter_by(
            event_type=EventType.CAPTCHA_FAILURE
        ).first()
        assert captcha_fail_log is not None

        # Verify failed_login_count remains 2 (not bumped or reset)
        user = User.query.filter_by(email=VALID_LOGIN["email"]).first()
        assert user.failed_login_count == 2

    def test_expired_captcha_rejects_login_and_logs_failure(self, client, db):
        """Expired CAPTCHA rejects login and logs CAPTCHA_FAILURE."""
        import time
        _register(client)
        client.get(LOGOUT_URL)

        # 2 failures
        _login(client, {"password": "WrongPassword@1"})
        _login(client, {"password": "WrongPassword@2"})

        # Expire session captcha
        with client.session_transaction() as sess:
            sess["captcha_expires_at"] = time.time() - 10

        r = client.post(
            LOGIN_URL,
            data={
                "email": VALID_LOGIN["email"],
                "password": VALID_LOGIN["password"],
                "captcha_input": "ANYCODE",
            },
            follow_redirects=True,
        )

        assert r.status_code == 200
        assert b"expired" in r.data.lower() or b"captcha" in r.data.lower()
        assert b"My Dashboard" not in r.data

        captcha_fail_log = ActivityLog.query.filter_by(
            event_type=EventType.CAPTCHA_FAILURE
        ).first()
        assert captcha_fail_log is not None

    def test_correct_captcha_with_wrong_password_increments_counter(self, client, db):
        """Correct CAPTCHA allows credential check; wrong password increments failed_login_count."""
        _register(client)
        client.get(LOGOUT_URL)

        _login(client, {"password": "WrongPassword@1"})
        _login(client, {"password": "WrongPassword@2"})

        with client.session_transaction() as sess:
            valid_captcha = sess.get("captcha_text")

        r = client.post(
            LOGIN_URL,
            data={
                "email": VALID_LOGIN["email"],
                "password": "WrongPassword@3",
                "captcha_input": valid_captcha,
            },
            follow_redirects=True,
        )

        assert r.status_code == 200
        assert b"Invalid email or password" in r.data

        # CAPTCHA was successful
        captcha_success_log = ActivityLog.query.filter_by(
            event_type=EventType.CAPTCHA_SUCCESS
        ).first()
        assert captcha_success_log is not None

        # failed_login_count incremented to 3
        user = User.query.filter_by(email=VALID_LOGIN["email"]).first()
        assert user.failed_login_count == 3

    def test_correct_captcha_with_correct_password_logs_in_and_resets(self, client, db):
        """Correct CAPTCHA + correct password logs in and resets failed_login_count and CAPTCHA."""
        _register(client)
        client.get(LOGOUT_URL)

        _login(client, {"password": "WrongPassword@1"})
        _login(client, {"password": "WrongPassword@2"})

        with client.session_transaction() as sess:
            valid_captcha = sess.get("captcha_text")

        r = client.post(
            LOGIN_URL,
            data={
                "email": VALID_LOGIN["email"],
                "password": VALID_LOGIN["password"],
                "captcha_input": valid_captcha,
            },
            follow_redirects=True,
        )

        assert r.status_code == 200
        assert b"My Dashboard" in r.data

        # failed_login_count reset to 0
        user = User.query.filter_by(email=VALID_LOGIN["email"]).first()
        assert user.failed_login_count == 0

        # Subsequent login does NOT require CAPTCHA
        client.get(LOGOUT_URL)
        r2 = client.get(LOGIN_URL)
        assert b"Verification Image" not in r2.data
        assert b"captcha_input" not in r2.data

    def test_dashboard_displays_historical_failed_login_count_after_success(self, client, db):
        """After 2 failed login attempts and then a successful login, User Dashboard shows Total Failed Login Attempts: 2."""
        _register(client)
        client.get(LOGOUT_URL)

        # 2 failed logins
        _login(client, {"password": "WrongPassword@1"})
        _login(client, {"password": "WrongPassword@2"})

        with client.session_transaction() as sess:
            valid_captcha = sess.get("captcha_text")

        # Successful login
        r = client.post(
            LOGIN_URL,
            data={
                "email": VALID_LOGIN["email"],
                "password": VALID_LOGIN["password"],
                "captcha_input": valid_captcha,
            },
            follow_redirects=True,
        )

        assert r.status_code == 200
        assert b"My Dashboard" in r.data

        # failed_login_count on model was reset to 0
        user = User.query.filter_by(email=VALID_LOGIN["email"]).first()
        assert user.failed_login_count == 0

        # Dashboard shows Total Failed Login Attempts: 2
        dash_resp = client.get(DASH_URL)
        assert dash_resp.status_code == 200
        assert b"Total Failed Login Attempts" in dash_resp.data
        assert b"2" in dash_resp.data


