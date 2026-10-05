"""
tests/test_bot_detection.py — Unit and integration tests for Bot Detection and Risk Scoring.

Covers:
- Risk engine weights and boundary classifications (0–30 NORMAL, 31–60 SUSPICIOUS, 61–100 HIGH_RISK)
- Clamping between 0 and 100
- Granular checks (repeated failed logins, repeated CAPTCHA failures, excessive activity, rapid bursts)
- Full behavioral analysis (analyze_behavior)
- ActivityLog risk updates and BOT_DETECTED event auditing
"""

from models.activity import ActivityLog, ActivityStatus, EventType, RiskLevel
from services.bot_detector import (
    analyze_behavior,
    check_excessive_activity,
    check_rapid_repeated_activity,
    check_repeated_captcha_failures,
    check_repeated_failed_logins,
    record_bot_detection,
    update_activity_risk,
)
from services.monitoring import log_event
from services.risk_engine import (
    THRESHOLD_NORMAL_MAX,
    THRESHOLD_SUSPICIOUS_MAX,
    WEIGHT_CAPTCHA_FAILURE,
    WEIGHT_EXCESSIVE_ACTIVITY,
    WEIGHT_FAILED_LOGIN,
    WEIGHT_REPEATED_SUSPICIOUS,
    calculate_risk_score,
    clamp_score,
    compute_risk_level,
)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Risk Engine Unit Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestRiskEngine:
    """Test risk weights, level classifications, and clamping logic."""

    def test_risk_weight_constants(self):
        assert WEIGHT_FAILED_LOGIN == 20
        assert WEIGHT_CAPTCHA_FAILURE == 25
        assert WEIGHT_EXCESSIVE_ACTIVITY == 30
        assert WEIGHT_REPEATED_SUSPICIOUS == 25

    def test_clamp_score(self):
        assert clamp_score(-10) == 0
        assert clamp_score(0) == 0
        assert clamp_score(45) == 45
        assert clamp_score(100) == 100
        assert clamp_score(150) == 100

    def test_compute_risk_level_boundaries(self):
        # 0–30: NORMAL
        assert compute_risk_level(0) == RiskLevel.NORMAL
        assert compute_risk_level(15) == RiskLevel.NORMAL
        assert compute_risk_level(30) == RiskLevel.NORMAL

        # 31–60: SUSPICIOUS
        assert compute_risk_level(31) == RiskLevel.SUSPICIOUS
        assert compute_risk_level(45) == RiskLevel.SUSPICIOUS
        assert compute_risk_level(60) == RiskLevel.SUSPICIOUS

        # 61–100: HIGH_RISK
        assert compute_risk_level(61) == RiskLevel.HIGH_RISK
        assert compute_risk_level(85) == RiskLevel.HIGH_RISK
        assert compute_risk_level(100) == RiskLevel.HIGH_RISK

    def test_calculate_risk_score_failed_logins(self):
        # 1 failed login: 20 -> NORMAL
        score, level, breakdown = calculate_risk_score(failed_logins=1)
        assert score == 20
        assert level == RiskLevel.NORMAL
        assert breakdown["failed_logins"] == 20

        # 2 failed logins: 40 -> SUSPICIOUS
        score, level, _ = calculate_risk_score(failed_logins=2)
        assert score == 40
        assert level == RiskLevel.SUSPICIOUS

    def test_calculate_risk_score_captcha_failures(self):
        # 1 CAPTCHA failure: 25 -> NORMAL
        score, level, breakdown = calculate_risk_score(captcha_failures=1)
        assert score == 25
        assert level == RiskLevel.NORMAL
        assert breakdown["captcha_failures"] == 25

        # 2 CAPTCHA failures: 50 -> SUSPICIOUS
        score, level, _ = calculate_risk_score(captcha_failures=2)
        assert score == 50
        assert level == RiskLevel.SUSPICIOUS

        # 3 CAPTCHA failures: 75 -> HIGH_RISK
        score, level, _ = calculate_risk_score(captcha_failures=3)
        assert score == 75
        assert level == RiskLevel.HIGH_RISK

    def test_calculate_risk_score_excessive_and_repeated_activity(self):
        # Excessive activity: +30
        score, level, _ = calculate_risk_score(has_excessive_activity=True)
        assert score == 30
        assert level == RiskLevel.NORMAL

        # Excessive (+30) + Repeated Suspicious (+25) = 55 -> SUSPICIOUS
        score, level, _ = calculate_risk_score(
            has_excessive_activity=True, has_repeated_suspicious=True
        )
        assert score == 55
        assert level == RiskLevel.SUSPICIOUS

        # Excessive (+30) + Repeated Suspicious (+25) + 1 Failed Login (+20) = 75 -> HIGH_RISK
        score, level, _ = calculate_risk_score(
            failed_logins=1,
            has_excessive_activity=True,
            has_repeated_suspicious=True,
        )
        assert score == 75
        assert level == RiskLevel.HIGH_RISK

    def test_calculate_risk_score_caps_at_100(self):
        score, level, _ = calculate_risk_score(
            failed_logins=5,          # 100
            captcha_failures=4,       # 100
            has_excessive_activity=True,  # 30
            has_repeated_suspicious=True, # 25
        )
        assert score == 100
        assert level == RiskLevel.HIGH_RISK


# ─────────────────────────────────────────────────────────────────────────────
# 2. Granular Bot Detection Checks
# ─────────────────────────────────────────────────────────────────────────────

class TestBotDetectionChecks:
    """Test individual pattern detection functions."""

    def test_check_repeated_failed_logins(self, app, db):
        ip = "192.0.2.1"
        # Initially 0
        res = check_repeated_failed_logins(ip_address=ip, threshold=3)
        assert res["triggered"] is False
        assert res["count"] == 0

        # Add 3 failed login logs
        for _ in range(3):
            log_event(event_type=EventType.LOGIN_FAILURE, ip_address=ip)

        res = check_repeated_failed_logins(ip_address=ip, threshold=3)
        assert res["triggered"] is True
        assert res["count"] == 3

    def test_check_repeated_captcha_failures(self, app, db):
        ip = "192.0.2.2"
        for _ in range(3):
            log_event(event_type=EventType.CAPTCHA_FAILURE, ip_address=ip)

        res = check_repeated_captcha_failures(ip_address=ip, threshold=3)
        assert res["triggered"] is True
        assert res["count"] == 3

    def test_check_excessive_activity(self, app, db):
        ip = "192.0.2.3"
        for i in range(20):
            log_event(
                event_type=EventType.SUSPICIOUS_REQUEST,
                description=f"Req {i}",
                ip_address=ip,
            )

        res = check_excessive_activity(ip_address=ip, threshold=20)
        assert res["triggered"] is True
        assert res["count"] >= 20

    def test_check_rapid_repeated_activity(self, app, db):
        ip = "192.0.2.4"
        for i in range(5):
            log_event(
                event_type=EventType.SUSPICIOUS_REQUEST,
                description=f"Burst {i}",
                ip_address=ip,
            )

        res = check_rapid_repeated_activity(ip_address=ip, threshold=5)
        assert res["triggered"] is True
        assert res["count"] >= 5


# ─────────────────────────────────────────────────────────────────────────────
# 3. Behavioral Analysis Integration
# ─────────────────────────────────────────────────────────────────────────────

class TestBehavioralAnalysis:
    """Test high-level analyze_behavior integration."""

    def test_analyze_clean_ip_returns_normal(self, app, db):
        ip = "198.51.100.1"
        res = analyze_behavior(ip_address=ip)
        assert res["risk_score"] == 0
        assert res["risk_level"] == RiskLevel.NORMAL
        assert res["is_suspicious"] is False
        assert res["is_high_risk"] is False
        assert len(res["flags"]) == 0

    def test_analyze_suspicious_behavior(self, app, db):
        ip = "198.51.100.2"
        # 2 failed logins (+40) -> SUSPICIOUS
        for _ in range(2):
            log_event(event_type=EventType.LOGIN_FAILURE, ip_address=ip)

        res = analyze_behavior(ip_address=ip)
        assert res["risk_score"] == 40
        assert res["risk_level"] == RiskLevel.SUSPICIOUS
        assert res["is_suspicious"] is True
        assert res["is_high_risk"] is False

    def test_analyze_high_risk_bot_behavior(self, app, db):
        ip = "198.51.100.3"
        # 3 failed logins (60) + 1 CAPTCHA failure (25) = 85 -> HIGH_RISK
        for _ in range(3):
            log_event(event_type=EventType.LOGIN_FAILURE, ip_address=ip)
        log_event(event_type=EventType.CAPTCHA_FAILURE, ip_address=ip)

        res = analyze_behavior(ip_address=ip)
        assert res["risk_score"] >= 85
        assert res["risk_level"] == RiskLevel.HIGH_RISK
        assert res["is_high_risk"] is True
        assert any("repeated_failed_logins" in f for f in res["flags"])


# ─────────────────────────────────────────────────────────────────────────────
# 4. ActivityLog Persistence & Updates
# ─────────────────────────────────────────────────────────────────────────────

class TestActivityRiskUpdates:
    """Test updating risk scores in existing ActivityLog entries and logging BOT_DETECTED."""

    def test_update_activity_risk(self, app, db):
        entry = log_event(
            event_type=EventType.LOGIN_FAILURE,
            ip_address="203.0.113.1",
            risk_score=20,
        )
        assert entry.risk_level == RiskLevel.NORMAL

        # Update to score 75
        updated = update_activity_risk(entry.id, 75)
        assert updated is not None
        assert updated.risk_score == 75
        assert updated.risk_level == RiskLevel.HIGH_RISK

        # Confirm persisted in DB
        db_record = db.session.get(ActivityLog, entry.id)
        assert db_record.risk_score == 75
        assert db_record.risk_level == RiskLevel.HIGH_RISK


    def test_record_bot_detection(self, app, db):
        ip = "203.0.113.2"
        for _ in range(3):
            log_event(event_type=EventType.LOGIN_FAILURE, ip_address=ip)

        bot_log = record_bot_detection(ip_address=ip)
        assert bot_log is not None
        assert bot_log.event_type == EventType.BOT_DETECTED
        assert "Automated bot behavior detected" in bot_log.description
        assert bot_log.risk_score >= 60


# ─────────────────────────────────────────────────────────────────────────────
# 5. End-to-End Suspicious Activity Detection & Admin Dashboard Metrics
# ─────────────────────────────────────────────────────────────────────────────

class TestSuspiciousLoginDetectionAndDashboard:
    """
    Test end-to-end suspicious activity detection for repeated failed logins:
    - 1 failed login -> NORMAL
    - repeated failed logins -> SUSPICIOUS
    - sufficiently repeated suspicious activity -> HIGH_RISK
    - Admin Dashboard metrics correctly reflect these risk levels
    """

    def test_single_failed_login_classified_normal(self, app, db, client):
        from models.user import User
        from services.monitoring import log_login_failure

        user = User(username="victim1", email="victim1@example.com")
        user.set_password("CorrectPass123!")
        db.session.add(user)
        db.session.commit()

        with app.test_request_context(environ_base={"REMOTE_ADDR": "198.51.100.10"}):
            log_login_failure(email="victim1@example.com", reason="Wrong password", user_id=user.id)

        logs = ActivityLog.query.filter_by(user_id=user.id).all()
        assert len(logs) == 1
        assert logs[0].risk_score == 20
        assert logs[0].risk_level == RiskLevel.NORMAL

    def test_repeated_failed_logins_classified_suspicious(self, app, db):
        from models.user import User
        from services.monitoring import log_login_failure

        user = User(username="victim2", email="victim2@example.com")
        user.set_password("CorrectPass123!")
        db.session.add(user)
        db.session.commit()

        # First failure -> NORMAL (20)
        with app.test_request_context(environ_base={"REMOTE_ADDR": "198.51.100.20"}):
            log_login_failure(email="victim2@example.com", reason="Wrong password", user_id=user.id)

        # Second failure -> SUSPICIOUS (40)
        with app.test_request_context(environ_base={"REMOTE_ADDR": "198.51.100.20"}):
            log_login_failure(email="victim2@example.com", reason="Wrong password", user_id=user.id)

        logs = ActivityLog.query.filter_by(user_id=user.id).order_by(ActivityLog.id.asc()).all()
        assert len(logs) == 2
        assert logs[0].risk_level == RiskLevel.NORMAL
        assert logs[1].risk_score == 40
        assert logs[1].risk_level == RiskLevel.SUSPICIOUS

    def test_sufficiently_repeated_activity_classified_high_risk(self, app, db):
        from models.user import User
        from services.monitoring import log_captcha_failure, log_login_failure

        user = User(username="victim3", email="victim3@example.com")
        user.set_password("CorrectPass123!")
        db.session.add(user)
        db.session.commit()

        ip = "198.51.100.30"
        # 3 failed logins (60)
        for _ in range(3):
            with app.test_request_context(environ_base={"REMOTE_ADDR": ip}):
                log_login_failure(email="victim3@example.com", reason="Wrong password", user_id=user.id)

        # 1 CAPTCHA failure (+25 -> 85)
        with app.test_request_context(environ_base={"REMOTE_ADDR": ip}):
            log_captcha_failure(user_id=user.id, reason="Bad captcha", ip_address=ip)

        logs = ActivityLog.query.filter_by(user_id=user.id).order_by(ActivityLog.id.asc()).all()
        assert len(logs) == 4
        # 4th event is high risk
        assert logs[3].risk_score >= 85
        assert logs[3].risk_level == RiskLevel.HIGH_RISK

    def test_admin_dashboard_metrics_reflect_risk_levels(self, app, db, client):
        from models.user import User
        from services.monitoring import log_captcha_failure, log_login_failure

        # Admin user
        admin = User(username="secadmin", email="secadmin@botmonitor.com", is_admin=True)
        admin.set_password("AdminSecure1!")
        # Target user
        target = User(username="target_user", email="target@botmonitor.com")
        target.set_password("TargetSecure1!")
        db.session.add_all([admin, target])
        db.session.commit()

        ip = "198.51.100.40"
        # 1st failure -> NORMAL (score 20)
        with app.test_request_context(environ_base={"REMOTE_ADDR": ip}):
            log_login_failure(email="target@botmonitor.com", reason="Wrong password", user_id=target.id)

        # 2nd failure -> SUSPICIOUS (score 40)
        with app.test_request_context(environ_base={"REMOTE_ADDR": ip}):
            log_login_failure(email="target@botmonitor.com", reason="Wrong password", user_id=target.id)

        # 3rd failure -> SUSPICIOUS (score 60)
        with app.test_request_context(environ_base={"REMOTE_ADDR": ip}):
            log_login_failure(email="target@botmonitor.com", reason="Wrong password", user_id=target.id)

        # 4th failure (CAPTCHA failure) -> HIGH_RISK (score 85)
        with app.test_request_context(environ_base={"REMOTE_ADDR": ip}):
            log_captcha_failure(user_id=target.id, reason="Wrong captcha", ip_address=ip)

        # Log in as admin
        client.post(
            "/auth/login",
            data={"email": "secadmin@botmonitor.com", "password": "AdminSecure1!"},
            follow_redirects=True,
        )

        # Check API stats
        stats_resp = client.get("/admin/api/stats")
        assert stats_resp.status_code == 200
        stats_data = stats_resp.get_json()

        assert stats_data["risk_distribution"]["NORMAL"] >= 1
        assert stats_data["risk_distribution"]["SUSPICIOUS"] >= 2
        assert stats_data["risk_distribution"]["HIGH_RISK"] >= 1

        # Check Admin Dashboard page HTML
        dash_resp = client.get("/admin/dashboard")
        assert dash_resp.status_code == 200
        assert b"Admin Security Dashboard" in dash_resp.data
