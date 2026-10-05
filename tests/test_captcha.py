"""
tests/test_captcha.py — CAPTCHA unit and integration tests (Phase 3).

Covers:
- Phase 1: CaptchaAttempt database model
- CAPTCHA text generation (length, charset, randomness)
- CAPTCHA image generation (PNG bytes, base64 encoding)
- Dedicated CAPTCHA challenge page (/captcha/challenge)
- Correct CAPTCHA submission (success, database audit, activity logging)
- Incorrect CAPTCHA submission (failure, database audit, activity logging, auto-regeneration)
- Expired CAPTCHA submission (expiration handling, failure audit)
- CAPTCHA regeneration endpoint (/captcha/refresh and JSON response)
- Standalone image streaming endpoint (/captcha/image)
- Session handling (answer in encrypted session only, single-use clearing)
- User-linked CAPTCHA attempts for authenticated sessions
- CSRF protection on CAPTCHA form
"""

import time
from flask import session
from models.activity import ActivityLog, ActivityStatus, EventType
from models.captcha import CaptchaAttempt
from models.user import User
from services.captcha_service import (
    CAPTCHA_CHARSET,
    create_captcha_session,
    generate_captcha_base64,
    generate_captcha_image,
    generate_captcha_text,
    is_captcha_expired,
    verify_captcha,
)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Database Model (Phase 1 Preserved)
# ─────────────────────────────────────────────────────────────────────────────

class TestCaptchaAttemptModel:
    """Verify CaptchaAttempt model construction and methods."""

    def test_create_failed_attempt(self, db):
        attempt = CaptchaAttempt(ip_address="127.0.0.1", success=False)
        db.session.add(attempt)
        db.session.commit()
        assert attempt.id is not None
        assert attempt.success is False

    def test_create_successful_attempt(self, db):
        attempt = CaptchaAttempt(ip_address="192.168.1.1", success=True)
        db.session.add(attempt)
        db.session.commit()
        assert attempt.success is True

    def test_to_dict(self, db):
        attempt = CaptchaAttempt(ip_address="10.0.0.1", success=True)
        db.session.add(attempt)
        db.session.commit()
        d = attempt.to_dict()
        assert d["ip_address"] == "10.0.0.1"
        assert d["success"] is True
        assert "created_at" in d


# ─────────────────────────────────────────────────────────────────────────────
# 2. CAPTCHA Generation Service
# ─────────────────────────────────────────────────────────────────────────────

class TestCaptchaGenerationService:
    """Test text and image generation logic."""

    def test_generate_captcha_text_default_length(self, app):
        text = generate_captcha_text()
        assert len(text) == 6
        assert all(c in CAPTCHA_CHARSET for c in text)

    def test_generate_captcha_text_custom_length(self, app):
        text = generate_captcha_text(length=8)
        assert len(text) == 8
        assert all(c in CAPTCHA_CHARSET for c in text)

    def test_generate_captcha_text_randomness(self, app):
        tokens = {generate_captcha_text() for _ in range(20)}
        # 20 randomly generated 6-char strings should be all unique
        assert len(tokens) == 20

    def test_generate_captcha_image_bytes(self, app):
        img_bytes = generate_captcha_image("AB23CD")
        assert isinstance(img_bytes, bytes)
        assert len(img_bytes) > 500  # Non-trivial PNG data
        # PNG signature check: \x89PNG\r\n\x1a\n
        assert img_bytes.startswith(b"\x89PNG\r\n\x1a\n")

    def test_generate_captcha_base64_data_uri(self, app):
        data_uri = generate_captcha_base64("TEST99")
        assert data_uri.startswith("data:image/png;base64,")
        assert len(data_uri) > 500


# ─────────────────────────────────────────────────────────────────────────────
# 3. Session & Verification Logic
# ─────────────────────────────────────────────────────────────────────────────

class TestCaptchaSessionAndVerification:
    """Test session lifecycle and verify_captcha function."""

    def test_create_captcha_session(self, app, client):
        with client.session_transaction() as sess:
            pass  # Ensure clean session
        with app.test_request_context():
            text, image_uri = create_captcha_session(length=5, expiry_seconds=60)
            assert len(text) == 5
            assert session["captcha_text"] == text
            assert session["captcha_expires_at"] > time.time()
            assert image_uri.startswith("data:image/png;base64,")


    def test_is_captcha_expired_false_for_fresh_challenge(self, app):
        with app.test_request_context():
            create_captcha_session(expiry_seconds=120)
            assert is_captcha_expired() is False

    def test_is_captcha_expired_true_for_past_timestamp(self, app):
        with app.test_request_context():
            session["captcha_text"] = "ABC12"
            session["captcha_expires_at"] = time.time() - 10
            assert is_captcha_expired() is True

    def test_verify_captcha_success(self, app, db):
        with app.test_request_context():
            text, _ = create_captcha_session()
            valid, msg = verify_captcha(text)
            assert valid is True
            assert "successful" in msg.lower()
            # Session text must be cleared (single-use)
            assert "captcha_text" not in session

            # Verify CaptchaAttempt record
            attempt = CaptchaAttempt.query.first()
            assert attempt is not None
            assert attempt.success is True

            # Verify ActivityLog record
            log = ActivityLog.query.filter_by(event_type=EventType.CAPTCHA_SUCCESS).first()
            assert log is not None
            assert log.status == ActivityStatus.SUCCESS

    def test_verify_captcha_failure_wrong_answer(self, app, db):
        with app.test_request_context():
            create_captcha_session()
            valid, msg = verify_captcha("WRONG_ANSWER")
            assert valid is False
            assert "incorrect" in msg.lower()

            # Verify CaptchaAttempt record
            attempt = CaptchaAttempt.query.first()
            assert attempt is not None
            assert attempt.success is False

            # Verify ActivityLog record
            log = ActivityLog.query.filter_by(event_type=EventType.CAPTCHA_FAILURE).first()
            assert log is not None
            assert log.status == ActivityStatus.FAILURE

    def test_verify_captcha_failure_when_expired(self, app, db):
        with app.test_request_context():
            session["captcha_text"] = "VALID9"
            session["captcha_expires_at"] = time.time() - 5  # Expired

            valid, msg = verify_captcha("VALID9")
            assert valid is False
            assert "expired" in msg.lower()

            attempt = CaptchaAttempt.query.first()
            assert attempt is not None
            assert attempt.success is False

            log = ActivityLog.query.filter_by(event_type=EventType.CAPTCHA_FAILURE).first()
            assert log is not None

    def test_verify_captcha_failure_when_missing_session(self, app, db):
        with app.test_request_context():
            session.clear()
            valid, msg = verify_captcha("SOMECODE")
            assert valid is False
            assert "no active" in msg.lower()

            attempt = CaptchaAttempt.query.first()
            assert attempt is not None
            assert attempt.success is False

    def test_single_use_prevents_replay(self, app, db):
        with app.test_request_context():
            text, _ = create_captcha_session()
            # First attempt: succeeds
            valid1, _ = verify_captcha(text)
            assert valid1 is True

            # Second attempt with same code: must fail because session was cleared
            valid2, _ = verify_captcha(text)
            assert valid2 is False


# ─────────────────────────────────────────────────────────────────────────────
# 4. Web Routes & Challenge Endpoints
# ─────────────────────────────────────────────────────────────────────────────

class TestCaptchaRoutes:
    """Test web routes (/captcha/challenge, /captcha/refresh, /captcha/image, /captcha/ping)."""

    def test_captcha_ping_endpoint(self, client):
        r = client.get("/captcha/ping")
        assert r.status_code == 200
        assert r.json["phase"] == 3

    def test_challenge_page_loads(self, client, db):
        r = client.get("/captcha/challenge")
        assert r.status_code == 200
        assert b"Security Challenge" in r.data
        assert b"Verification Image" in r.data
        assert b"captcha_input" in r.data
        assert b"Refresh Image" in r.data

    def test_challenge_page_alias_root(self, client, db):
        r = client.get("/captcha/")
        assert r.status_code == 200
        assert b"Security Challenge" in r.data

    def test_image_streaming_endpoint(self, client, db):
        # Trigger session challenge first
        client.get("/captcha/challenge")
        r = client.get("/captcha/image")
        assert r.status_code == 200
        assert r.content_type == "image/png"
        assert r.data.startswith(b"\x89PNG\r\n\x1a\n")

    def test_refresh_endpoint_redirects(self, client, db):
        client.get("/captcha/challenge")
        with client.session_transaction() as sess:
            first_text = sess.get("captcha_text")

        r = client.get("/captcha/refresh", follow_redirects=False)
        assert r.status_code == 302
        assert "/captcha/challenge" in r.headers["Location"]

        with client.session_transaction() as sess:
            second_text = sess.get("captcha_text")

        assert second_text is not None

    def test_refresh_endpoint_json_api(self, client, db):
        r = client.get("/captcha/refresh?format=json")
        assert r.status_code == 200
        data = r.get_json()
        assert data["success"] is True
        assert "captcha_image" in data
        assert data["captcha_image"].startswith("data:image/png;base64,")

    def test_submit_correct_captcha_redirects(self, client, db):
        # 1. Load challenge page to generate session
        client.get("/captcha/challenge")

        with client.session_transaction() as sess:
            expected = sess.get("captcha_text")

        # 2. Submit correct answer
        r = client.post(
            "/captcha/challenge",
            data={"captcha_input": expected},
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"Security check passed successfully" in r.data

        # 3. Verify audit record
        attempt = CaptchaAttempt.query.first()
        assert attempt is not None
        assert attempt.success is True

    def test_submit_correct_captcha_with_next_url(self, client, db):
        client.get("/captcha/challenge?next=/auth/login")

        with client.session_transaction() as sess:
            expected = sess.get("captcha_text")

        r = client.post(
            "/captcha/challenge?next=/auth/login",
            data={"captcha_input": expected},
            follow_redirects=False,
        )
        assert r.status_code == 302
        assert "/auth/login" in r.headers["Location"]

    def test_submit_incorrect_captcha_redisplays_with_error(self, client, db):
        client.get("/captcha/challenge")

        r = client.post(
            "/captcha/challenge",
            data={"captcha_input": "INCORRECT_CODE"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"Incorrect CAPTCHA answer" in r.data
        # Page should still render challenge with new image
        assert b"Security Challenge" in r.data

        # Verify failed attempt recorded
        attempt = CaptchaAttempt.query.first()
        assert attempt is not None
        assert attempt.success is False

    def test_submit_blank_captcha_rejected(self, client, db):
        client.get("/captcha/challenge")

        r = client.post(
            "/captcha/challenge",
            data={"captcha_input": ""},
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"Security Challenge" in r.data

    def test_authenticated_user_linked_to_captcha_attempt(self, client, db):
        # Create and login user
        user = User(username="testcaptcha", email="captcha@example.com")
        user.set_password("Secure@Pass1")
        db.session.add(user)
        db.session.commit()

        client.post(
            "/auth/login",
            data={"email": "captcha@example.com", "password": "Secure@Pass1"},
        )

        # Request and solve CAPTCHA
        client.get("/captcha/challenge")
        with client.session_transaction() as sess:
            code = sess.get("captcha_text")

        client.post("/captcha/challenge", data={"captcha_input": code})

        # Check that user_id is properly recorded
        attempt = CaptchaAttempt.query.filter_by(user_id=user.id).first()
        assert attempt is not None
        assert attempt.success is True
        assert attempt.user_id == user.id

        log = ActivityLog.query.filter_by(
            event_type=EventType.CAPTCHA_SUCCESS, user_id=user.id
        ).first()
        assert log is not None


# ─────────────────────────────────────────────────────────────────────────────
# 5. CSRF Protection
# ─────────────────────────────────────────────────────────────────────────────

class TestCaptchaCSRF:
    """Verify CSRF protection on CAPTCHA form."""

    def test_captcha_form_has_hidden_tag(self):
        from forms.captcha_forms import CaptchaForm
        assert hasattr(CaptchaForm, "hidden_tag")

    def test_captcha_csrf_token_in_html_with_csrf_enabled(self):
        """Challenge page renders a csrf_token input when CSRF is enabled."""
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
                r = c.get("/captcha/challenge")
                assert b"csrf_token" in r.data

