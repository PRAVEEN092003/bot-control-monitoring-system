"""
tests/test_activity.py — User activity monitoring and event filtering tests.

Covers:
- ActivityLog persistence and query helpers
- User security event recording (registration, login, logout, CAPTCHA)
- Authentication requirement for /user/activity
- User activity log rendering and context
- Cross-user data isolation (users only see their own audit log)
- Event type filtering (/user/activity?event_type=...)
- Dashboard filtering (/user/dashboard?event_type=...)
- Graceful handling of empty or unknown filter values
"""

from models.activity import ActivityLog, ActivityStatus, EventType, RiskLevel
from models.user import User
from services.monitoring import (
    log_captcha_failure,
    log_captcha_success,
    log_event,
    log_login_failure,
    log_login_success,
    log_logout,
    log_register_failure,
    log_register_success,
)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Monitoring Service & Model Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestActivityMonitoringService:
    """Test log_event and convenience helpers in services/monitoring.py."""

    def test_log_event_persists_to_db(self, app, db):
        with app.test_request_context("/some/endpoint"):
            entry = log_event(
                event_type=EventType.LOGIN_SUCCESS,
                description="Test event description",
                user_id=1,
                risk_score=0,
                status=ActivityStatus.SUCCESS,
            )
            assert entry is not None
            assert entry.id is not None
            assert entry.event_type == EventType.LOGIN_SUCCESS
            assert entry.risk_level == RiskLevel.NORMAL

    def test_log_login_helpers(self, app, db):
        with app.test_request_context():
            log_login_success(user_id=10, username="alice")
            log_login_failure(email="bob@example.com", reason="Bad password")

            success_log = ActivityLog.query.filter_by(event_type=EventType.LOGIN_SUCCESS).first()
            fail_log = ActivityLog.query.filter_by(event_type=EventType.LOGIN_FAILURE).first()

            assert success_log is not None
            assert success_log.user_id == 10
            assert "alice" in success_log.description

            assert fail_log is not None
            assert fail_log.status == ActivityStatus.FAILURE

    def test_log_captcha_helpers(self, app, db):
        with app.test_request_context():
            log_captcha_success(user_id=5)
            log_captcha_failure(user_id=5, reason="Timeout")

            cap_succ = ActivityLog.query.filter_by(event_type=EventType.CAPTCHA_SUCCESS).first()
            cap_fail = ActivityLog.query.filter_by(event_type=EventType.CAPTCHA_FAILURE).first()

            assert cap_succ is not None
            assert cap_succ.status == ActivityStatus.SUCCESS
            assert cap_fail is not None
            assert cap_fail.status == ActivityStatus.FAILURE


# ─────────────────────────────────────────────────────────────────────────────
# 2. User Activity Page & Authorization
# ─────────────────────────────────────────────────────────────────────────────

class TestUserActivityPage:
    """Test /user/activity endpoint authorization and rendering."""

    def test_activity_page_requires_login(self, client, db):
        """Unauthenticated requests are redirected to /auth/login."""
        r = client.get("/user/activity", follow_redirects=False)
        assert r.status_code == 302
        assert "/auth/login" in r.headers["Location"]

    def test_activity_page_loads_for_authenticated_user(self, client, db):
        # Register and login
        user = User(username="auditor", email="auditor@example.com")
        user.set_password("Secure@Pass1")
        db.session.add(user)
        db.session.commit()

        client.post(
            "/auth/login",
            data={"email": "auditor@example.com", "password": "Secure@Pass1"},
        )

        r = client.get("/user/activity")
        assert r.status_code == 200
        assert b"Security Activity Log" in r.data
        assert b"Filter by Event" in r.data
        assert b"auditor" in r.data

    def test_activity_page_displays_logged_events(self, client, db):
        user = User(username="eventuser", email="event@example.com")
        user.set_password("Secure@Pass1")
        db.session.add(user)
        db.session.commit()

        # Login creates a LOGIN_SUCCESS log
        client.post(
            "/auth/login",
            data={"email": "event@example.com", "password": "Secure@Pass1"},
        )

        # Add a custom event
        log_event(
            event_type=EventType.CAPTCHA_SUCCESS,
            description="Solved image challenge in 3s",
            user_id=user.id,
        )

        r = client.get("/user/activity")
        assert r.status_code == 200
        assert b"Login Success" in r.data
        assert b"Captcha Success" in r.data
        assert b"Solved image challenge in 3s" in r.data

    def test_user_activity_isolation(self, client, db):
        """User 1 must NOT see events belonging to User 2."""
        u1 = User(username="userone", email="u1@example.com")
        u1.set_password("Pass@Word1")
        u2 = User(username="usertwo", email="u2@example.com")
        u2.set_password("Pass@Word2")
        db.session.add_all([u1, u2])
        db.session.commit()

        # Create private events for u2
        log_event(
            event_type=EventType.CAPTCHA_SUCCESS,
            description="SECRET_U2_EVENT_TEXT",
            user_id=u2.id,
        )

        # Login as u1
        client.post("/auth/login", data={"email": "u1@example.com", "password": "Pass@Word1"})

        r = client.get("/user/activity")
        assert r.status_code == 200
        assert b"SECRET_U2_EVENT_TEXT" not in r.data


# ─────────────────────────────────────────────────────────────────────────────
# 3. Activity Filtering
# ─────────────────────────────────────────────────────────────────────────────

class TestActivityFiltering:
    """Test filtering by event_type on /user/activity and /user/dashboard."""

    def test_filter_by_event_type_shows_only_matching(self, client, db):
        user = User(username="filteruser", email="filter@example.com")
        user.set_password("Pass@Word1")
        db.session.add(user)
        db.session.commit()

        # Add specific events for user
        log_event(event_type=EventType.LOGIN_SUCCESS, description="EV_LOGIN_OK", user_id=user.id)
        log_event(event_type=EventType.CAPTCHA_FAILURE, description="EV_CAPTCHA_FAIL", user_id=user.id)
        log_event(event_type=EventType.LOGOUT, description="EV_LOGOUT_OK", user_id=user.id)

        # Login
        client.post("/auth/login", data={"email": "filter@example.com", "password": "Pass@Word1"})

        # 1. Filter for CAPTCHA_FAILURE only
        r = client.get(f"/user/activity?event_type={EventType.CAPTCHA_FAILURE}")
        assert r.status_code == 200
        assert b"EV_CAPTCHA_FAIL" in r.data
        assert b"EV_LOGOUT_OK" not in r.data

        # 2. Filter for LOGOUT only
        r = client.get(f"/user/activity?event_type={EventType.LOGOUT}")
        assert r.status_code == 200
        assert b"EV_LOGOUT_OK" in r.data
        assert b"EV_CAPTCHA_FAIL" not in r.data

    def test_filter_all_shows_all_events(self, client, db):
        user = User(username="alluser", email="all@example.com")
        user.set_password("Pass@Word1")
        db.session.add(user)
        db.session.commit()

        log_event(event_type=EventType.LOGIN_SUCCESS, description="EV_LOGIN_A", user_id=user.id)
        log_event(event_type=EventType.CAPTCHA_SUCCESS, description="EV_CAPTCHA_B", user_id=user.id)

        client.post("/auth/login", data={"email": "all@example.com", "password": "Pass@Word1"})

        r = client.get("/user/activity?event_type=all")
        assert r.status_code == 200
        assert b"EV_LOGIN_A" in r.data
        assert b"EV_CAPTCHA_B" in r.data

    def test_filter_unknown_event_type_shows_empty_state(self, client, db):
        user = User(username="emptyuser", email="empty@example.com")
        user.set_password("Pass@Word1")
        db.session.add(user)
        db.session.commit()

        client.post("/auth/login", data={"email": "empty@example.com", "password": "Pass@Word1"})

        r = client.get("/user/activity?event_type=nonexistent_event")
        assert r.status_code == 200
        assert b"No events found" in r.data

    def test_dashboard_filtering(self, client, db):
        user = User(username="dashfilter", email="dashfilter@example.com")
        user.set_password("Pass@Word1")
        db.session.add(user)
        db.session.commit()

        log_event(event_type=EventType.CAPTCHA_SUCCESS, description="DASH_CAPTCHA_OK", user_id=user.id)
        log_event(event_type=EventType.LOGOUT, description="DASH_LOGOUT_OK", user_id=user.id)

        client.post("/auth/login", data={"email": "dashfilter@example.com", "password": "Pass@Word1"})

        r = client.get(f"/user/dashboard?event_type={EventType.CAPTCHA_SUCCESS}")
        assert r.status_code == 200
        assert b"DASH_CAPTCHA_OK" in r.data
        assert b"DASH_LOGOUT_OK" not in r.data

    def test_dashboard_total_failed_logins_metric(self, client, db):
        """Dashboard displays historical LOGIN_FAILURE count as Total Failed Login Attempts."""
        user = User(username="metricuser", email="metric@example.com")
        user.set_password("Pass@Word1")
        db.session.add(user)
        db.session.commit()

        # Log 2 historical failure events
        log_event(event_type=EventType.LOGIN_FAILURE, description="Failed login attempt", user_id=user.id)
        log_event(event_type=EventType.LOGIN_FAILURE, description="Failed login attempt", user_id=user.id)

        # Login successfully
        client.post("/auth/login", data={"email": "metric@example.com", "password": "Pass@Word1"})

        r = client.get("/user/dashboard")
        assert r.status_code == 200
        assert b"Total Failed Login Attempts" in r.data
        assert b"2" in r.data

