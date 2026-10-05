"""
tests/test_security.py — Security hardening tests (Phase 9).

Covers:
- Security HTTP response headers (X-Content-Type-Options, X-Frame-Options, CSP, etc.)
- Open redirect defense (rejecting external/protocol-relative next URLs)
- Cookie security attributes (HttpOnly, SameSite, Secure)
- Production configuration hardening (DEBUG=False, Secure cookies)
- Password protection (bcrypt hashing, to_dict excludes hashes)
- Error response sanitization (no internal traces leaked)
"""

from config import ProductionConfig, DevelopmentConfig, TestingConfig
from models.user import User


class TestSecurityHeaders:
    """Verify that all responses include defensive cybersecurity HTTP headers."""

    def test_security_headers_present_on_routes(self, client):
        r = client.get("/auth/login")
        assert r.status_code == 200

        # Check defensive headers
        assert r.headers.get("X-Content-Type-Options") == "nosniff"
        assert r.headers.get("X-Frame-Options") == "SAMEORIGIN"
        assert "1; mode=block" in r.headers.get("X-XSS-Protection", "")
        assert r.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert "geolocation=()" in r.headers.get("Permissions-Policy", "")
        assert "Content-Security-Policy" in r.headers
        assert "default-src 'self'" in r.headers["Content-Security-Policy"]


class TestOpenRedirectDefense:
    """Verify that user-supplied next parameters cannot redirect to external domains."""

    def test_auth_login_rejects_external_redirect(self, client, db):
        user = User(username="sec_user", email="sec@example.com")
        user.set_password("Secure@Pass1")
        db.session.add(user)
        db.session.commit()

        # Malicious next URL targets
        evil_targets = [
            "https://evil.com/phishing",
            "http://attacker.com",
            "//evil.com/stealer",
            "javascript:alert(1)",
        ]

        for evil in evil_targets:
            r = client.post(
                f"/auth/login?next={evil}",
                data={"email": "sec@example.com", "password": "Secure@Pass1"},
                follow_redirects=False,
            )
            # Must redirect internally to user dashboard, NOT to evil URL
            assert r.status_code == 302
            assert "evil.com" not in r.headers["Location"]
            assert "attacker.com" not in r.headers["Location"]
            assert "/user/dashboard" in r.headers["Location"]

    def test_auth_login_allows_safe_relative_redirect(self, client, db):
        user = User(username="sec_user2", email="sec2@example.com")
        user.set_password("Secure@Pass1")
        db.session.add(user)
        db.session.commit()

        r = client.post(
            "/auth/login?next=/user/activity",
            data={"email": "sec2@example.com", "password": "Secure@Pass1"},
            follow_redirects=False,
        )
        assert r.status_code == 302
        assert "/user/activity" in r.headers["Location"]


class TestPasswordSecurity:
    """Verify password protection and serialization safety."""

    def test_password_hash_not_exposed_in_to_dict(self, db):
        user = User(username="hash_test", email="hash@example.com")
        user.set_password("Pass#Word123")
        db.session.add(user)
        db.session.commit()

        d = user.to_dict()
        assert "password_hash" not in d
        assert "password" not in d
        assert "Pass#Word123" not in str(d)

    def test_bcrypt_hash_format(self, db):
        user = User(username="hash_test2", email="hash2@example.com")
        user.set_password("Pass#Word123")
        assert user.password_hash.startswith("$2b$") or user.password_hash.startswith("$2a$")


class TestProductionConfigurationHardening:
    """Verify that ProductionConfig enforces strict production settings."""

    def test_production_config_properties(self):
        assert ProductionConfig.DEBUG is False
        assert ProductionConfig.TESTING is False
        assert ProductionConfig.SESSION_COOKIE_SECURE is True
        assert ProductionConfig.REMEMBER_COOKIE_SECURE is True
        assert ProductionConfig.SESSION_COOKIE_HTTPONLY is True
        assert ProductionConfig.SESSION_COOKIE_SAMESITE in ("Lax", "Strict")


class TestErrorResponsesSanitized:
    """Verify custom error handlers return clean responses without stack traces."""

    def test_404_error_response(self, client):
        r = client.get("/non-existent-security-endpoint-xyz")
        assert r.status_code == 404
        data = r.get_json()
        assert data["error"] == "Not Found"

    def test_405_error_response(self, client):
        # GET on POST-only endpoint
        r = client.get("/admin/block-ip")
        assert r.status_code in (405, 302)  # 302 if login required or 405
