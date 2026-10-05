"""
tests/test_admin.py — Unit and integration tests for Admin Dashboard and Management.

Covers:
- Admin authorization enforcement (@admin_required): anonymous -> 302, non-admin -> 403, admin -> 200
- Admin Dashboard KPI calculation (users, events, captcha pass/fail, suspicious, high-risk, blocked IPs)
- Dashboard filtering (event_type, risk_level, search keyword)
- Security audit logs viewer (/admin/logs) with multi-criteria filters
- User directory overview (/admin/users)
- Blocked IPs management (/admin/blocked-ips, manual block, manual unblock)
- Stats JSON API endpoint (/admin/api/stats)
- Health-check ping (/admin/ping)
"""

from models.activity import ActivityLog, EventType, RiskLevel
from models.blocked_ip import BlockedIP
from models.captcha import CaptchaAttempt
from models.user import User
from services.monitoring import log_event


# ── Fixtures / Helpers ─────────────────────────────────────────────────────────

def _create_admin(db) -> User:
    """Create and return an admin user."""
    admin = User(username="secops_admin", email="admin@example.com", is_admin=True)
    admin.set_password("Admin@Pass1")
    db.session.add(admin)
    db.session.commit()
    return admin


def _create_regular_user(db) -> User:
    """Create and return a regular non-admin user."""
    user = User(username="regular_user", email="user@example.com", is_admin=False)
    user.set_password("User@Pass1")
    db.session.add(user)
    db.session.commit()
    return user


def _login_as(client, email: str, password: str):
    """Perform login POST request."""
    return client.post(
        "/auth/login",
        data={"email": email, "password": password},
        follow_redirects=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. Authorization & Access Control
# ─────────────────────────────────────────────────────────────────────────────

class TestAdminAuthorization:
    """Verify that all admin routes are protected against unauthorized access."""

    ADMIN_ROUTES = [
        "/admin/",
        "/admin/dashboard",
        "/admin/logs",
        "/admin/users",
        "/admin/blocked-ips",
        "/admin/api/stats",
    ]

    def test_anonymous_access_redirects_to_login(self, client, db):
        for route in self.ADMIN_ROUTES:
            r = client.get(route, follow_redirects=False)
            assert r.status_code == 302
            assert "/auth/login" in r.headers["Location"]

    def test_regular_user_access_returns_403(self, client, db):
        user = _create_regular_user(db)
        _login_as(client, user.email, "User@Pass1")

        for route in self.ADMIN_ROUTES:
            r = client.get(route)
            assert r.status_code == 403

    def test_admin_access_allowed(self, client, db):
        admin = _create_admin(db)
        _login_as(client, admin.email, "Admin@Pass1")

        for route in self.ADMIN_ROUTES:
            r = client.get(route)
            assert r.status_code == 200


# ─────────────────────────────────────────────────────────────────────────────
# 2. Dashboard KPIs & Metrics Calculation
# ─────────────────────────────────────────────────────────────────────────────

class TestAdminDashboardMetrics:
    """Verify accurate aggregation of dashboard statistics."""

    def test_dashboard_renders_kpis(self, client, db):
        admin = _create_admin(db)
        _create_regular_user(db)

        # Seed sample events
        log_event(event_type=EventType.LOGIN_SUCCESS, risk_score=0)
        log_event(event_type=EventType.BOT_DETECTED, risk_score=80)
        log_event(event_type=EventType.SUSPICIOUS_REQUEST, risk_score=40)

        # Seed captcha attempts
        db.session.add(CaptchaAttempt(ip_address="1.1.1.1", success=True))
        db.session.add(CaptchaAttempt(ip_address="2.2.2.2", success=False))

        # Seed blocked IP
        from services.ip_blocker import block_ip
        block_ip("198.51.100.77", reason="Test block", duration_minutes=30)
        db.session.commit()

        _login_as(client, admin.email, "Admin@Pass1")
        r = client.get("/admin/dashboard")
        assert r.status_code == 200
        assert b"Admin Security Dashboard" in r.data
        assert b"Security Event Distribution" in r.data
        assert b"Risk Level Breakdown" in r.data
        assert b"CAPTCHA Outcomes" in r.data

    def test_api_stats_json_endpoint(self, client, db):
        admin = _create_admin(db)
        _login_as(client, admin.email, "Admin@Pass1")

        r = client.get("/admin/api/stats")
        assert r.status_code == 200
        data = r.get_json()
        assert "total_users" in data
        assert "total_events" in data
        assert "captcha_stats" in data
        assert "risk_distribution" in data
        assert data["total_users"] >= 1


# ─────────────────────────────────────────────────────────────────────────────
# 3. Filtering & Search
# ─────────────────────────────────────────────────────────────────────────────

class TestAdminFiltering:
    """Verify event-type, risk-level, and text search on admin pages."""

    def test_dashboard_filtering_by_event_type(self, client, db):
        admin = _create_admin(db)
        log_event(event_type=EventType.BOT_DETECTED, description="BOT_ALPHA", risk_score=80)
        log_event(event_type=EventType.LOGOUT, description="LOGOUT_BETA", risk_score=0)

        _login_as(client, admin.email, "Admin@Pass1")

        # Filter by BOT_DETECTED
        r = client.get(f"/admin/dashboard?event_type={EventType.BOT_DETECTED}")
        assert r.status_code == 200
        assert b"BOT_ALPHA" in r.data
        assert b"LOGOUT_BETA" not in r.data

    def test_logs_filtering_by_risk_level(self, client, db):
        admin = _create_admin(db)
        log_event(event_type=EventType.BOT_DETECTED, description="DANGER_EVENT", risk_score=85)
        log_event(event_type=EventType.LOGIN_SUCCESS, description="SAFE_EVENT", risk_score=0)

        _login_as(client, admin.email, "Admin@Pass1")

        # Filter by HIGH_RISK
        r = client.get("/admin/logs?risk_level=HIGH_RISK")
        assert r.status_code == 200
        assert b"DANGER_EVENT" in r.data
        assert b"SAFE_EVENT" not in r.data

    def test_logs_search_by_keyword(self, client, db):
        admin = _create_admin(db)
        log_event(event_type=EventType.SUSPICIOUS_REQUEST, description="SQLi probe detected in query", risk_score=50)
        log_event(event_type=EventType.LOGIN_SUCCESS, description="Normal login from home", risk_score=0)

        _login_as(client, admin.email, "Admin@Pass1")

        r = client.get("/admin/logs?q=SQLi")
        assert r.status_code == 200
        assert b"SQLi probe detected in query" in r.data
        assert b"Normal login from home" not in r.data

    def test_logs_pagination(self, client, db):
        admin = _create_admin(db)
        # Create 12 distinct events
        for i in range(12):
            log_event(
                event_type=EventType.LOGIN_SUCCESS,
                description=f"PaginationEvent_{i:02d}",
                risk_score=0,
            )

        _login_as(client, admin.email, "Admin@Pass1")

        # Page 1 with per_page=5
        r_p1 = client.get("/admin/logs?per_page=5&page=1")
        assert r_p1.status_code == 200
        assert b"Showing Page" in r_p1.data
        assert b"PaginationEvent_11" in r_p1.data

        # Page 3 with per_page=5
        r_p3 = client.get("/admin/logs?per_page=5&page=3")
        assert r_p3.status_code == 200
        assert b"PaginationEvent_00" in r_p3.data

    def test_logs_date_range_filtering(self, client, db):
        from datetime import datetime, timedelta, timezone
        admin = _create_admin(db)

        now = datetime.now(timezone.utc)
        yesterday = now - timedelta(days=1)

        # Older event
        old_ev = ActivityLog(
            event_type=EventType.LOGIN_FAILURE,
            description="OLD_EVENT_YESTERDAY",
            ip_address="198.51.100.1",
            risk_score=20,
            created_at=yesterday,
        )
        db.session.add(old_ev)
        db.session.commit()

        # Today event
        log_event(
            event_type=EventType.LOGIN_SUCCESS,
            description="TODAY_FRESH_EVENT",
            risk_score=0,
        )

        _login_as(client, admin.email, "Admin@Pass1")

        today_str = now.strftime("%Y-%m-%d")
        r = client.get(f"/admin/logs?date_from={today_str}&date_to={today_str}")
        assert r.status_code == 200
        assert b"TODAY_FRESH_EVENT" in r.data
        assert b"OLD_EVENT_YESTERDAY" not in r.data

    def test_logs_status_filtering(self, client, db):
        from models.activity import ActivityStatus
        admin = _create_admin(db)

        log_event(
            event_type=EventType.RATE_LIMIT_EXCEEDED,
            description="RATE_LIMIT_BLOCKED_EVENT",
            status=ActivityStatus.BLOCKED,
            risk_score=40,
        )
        log_event(
            event_type=EventType.LOGIN_SUCCESS,
            description="REGULAR_SUCCESS_EVENT",
            status=ActivityStatus.SUCCESS,
            risk_score=0,
        )

        _login_as(client, admin.email, "Admin@Pass1")

        r = client.get("/admin/logs?status=blocked")
        assert r.status_code == 200
        assert b"RATE_LIMIT_BLOCKED_EVENT" in r.data
        assert b"REGULAR_SUCCESS_EVENT" not in r.data


# ─────────────────────────────────────────────────────────────────────────────
# 4. User Directory & Blocked IP Management
# ─────────────────────────────────────────────────────────────────────────────

class TestAdminManagementViews:
    """Test user directory and blocked IP actions."""

    def test_users_directory_lists_registered_accounts(self, client, db):
        admin = _create_admin(db)
        user = _create_regular_user(db)
        _login_as(client, admin.email, "Admin@Pass1")

        r = client.get("/admin/users")
        assert r.status_code == 200
        assert b"User Accounts" in r.data
        assert admin.username.encode() in r.data
        assert user.username.encode() in r.data

    def test_manual_block_and_unblock_ip_actions(self, client, db):
        admin = _create_admin(db)
        _login_as(client, admin.email, "Admin@Pass1")

        target_ip = "198.51.100.222"

        # 1. Block IP
        r_block = client.post(
            "/admin/block-ip",
            data={"ip_address": target_ip, "reason": "Admin manual block", "duration": 45},
            follow_redirects=True,
        )
        assert r_block.status_code == 200
        assert b"has been temporarily blocked" in r_block.data
        assert target_ip.encode() in r_block.data

        # 2. Unblock IP
        r_unblock = client.post(
            "/admin/unblock-ip",
            data={"ip_address": target_ip, "note": "False positive resolved"},
            follow_redirects=True,
        )
        assert r_unblock.status_code == 200
        assert b"has been unblocked" in r_unblock.data

    def test_admin_ping_endpoint(self, client, db):
        r = client.get("/admin/ping")
        assert r.status_code == 200
        assert r.json["phase"] == 7

