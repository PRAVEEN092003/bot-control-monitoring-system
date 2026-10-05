"""
tests/test_rate_limit.py — Rate limiting and temporary IP blocking tests.

Covers:
- BlockedIP database model (properties, expiration, deactivation)
- IP blocker service (block_ip, unblock_ip, is_ip_blocked, get_active_blocks)
- Automatic block expiration on evaluation (lazy unblock + audit log)
- 403 Forbidden middleware enforcement for blocked IPs
- Automatic access restoration after unblock or expiry
- Rate limiting enforcement (429 Too Many Requests)
- ActivityLog recording of RATE_LIMIT_EXCEEDED events
"""

from datetime import datetime, timedelta, timezone
from flask import jsonify

from config import BaseConfig
from extensions import db as _db
from models.activity import ActivityLog, ActivityStatus, EventType
from models.blocked_ip import BlockedIP
from services.ip_blocker import (
    block_ip,
    get_active_blocks,
    is_ip_blocked,
    unblock_ip,
)


# ─────────────────────────────────────────────────────────────────────────────
# 1. BlockedIP Model Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestBlockedIPModel:
    """Test BlockedIP ORM model methods and properties."""

    def test_create_blocked_ip(self, db):
        expires = datetime.now(timezone.utc) + timedelta(minutes=30)
        record = BlockedIP(
            ip_address="198.51.100.10",
            reason="High risk score",
            risk_score=75,
            expires_at=expires,
            active=True,
        )
        db.session.add(record)
        db.session.commit()

        assert record.id is not None
        assert record.is_expired is False
        assert record.is_currently_blocked is True

    def test_expired_property(self, db):
        past = datetime.now(timezone.utc) - timedelta(minutes=5)
        record = BlockedIP(
            ip_address="198.51.100.11",
            reason="Old block",
            expires_at=past,
            active=True,
        )
        db.session.add(record)
        db.session.commit()

        assert record.is_expired is True
        assert record.is_currently_blocked is False

    def test_deactivate_method(self, db):
        future = datetime.now(timezone.utc) + timedelta(minutes=20)
        record = BlockedIP(
            ip_address="198.51.100.12",
            reason="Test block",
            expires_at=future,
            active=True,
        )
        db.session.add(record)
        db.session.commit()

        record.deactivate(note="Admin cleared block")
        db.session.commit()

        assert record.active is False
        assert record.admin_note == "Admin cleared block"
        assert record.is_currently_blocked is False

    def test_to_dict(self, db):
        future = datetime.now(timezone.utc) + timedelta(minutes=15)
        record = BlockedIP(
            ip_address="198.51.100.13",
            reason="Dict test",
            risk_score=65,
            expires_at=future,
            active=True,
        )
        db.session.add(record)
        db.session.commit()

        d = record.to_dict()
        assert d["ip_address"] == "198.51.100.13"
        assert d["reason"] == "Dict test"
        assert d["risk_score"] == 65
        assert d["active"] is True
        assert d["is_currently_blocked"] is True


# ─────────────────────────────────────────────────────────────────────────────
# 2. IP Blocker Service Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestIPBlockerService:
    """Test block_ip, unblock_ip, is_ip_blocked, and automatic expiration."""

    def test_block_ip_creates_record_and_audit_log(self, app, db):
        ip = "203.0.113.50"
        record = block_ip(ip, reason="Bot burst detected", duration_minutes=15, risk_score=80)

        assert record.id is not None
        assert record.active is True
        assert record.risk_score == 80

        # Check is_ip_blocked
        blocked, active_rec = is_ip_blocked(ip)
        assert blocked is True
        assert active_rec is not None
        assert active_rec.ip_address == ip

        # Check ActivityLog
        log = ActivityLog.query.filter_by(
            event_type=EventType.IP_BLOCKED, ip_address=ip
        ).first()
        assert log is not None
        assert log.status == ActivityStatus.BLOCKED
        assert log.risk_score == 80

    def test_unblock_ip_deactivates_and_logs(self, app, db):
        ip = "203.0.113.51"
        block_ip(ip, reason="Temporary ban", duration_minutes=30)
        assert is_ip_blocked(ip)[0] is True

        success = unblock_ip(ip, admin_note="Support cleared ban")
        assert success is True
        assert is_ip_blocked(ip)[0] is False

        log = ActivityLog.query.filter_by(
            event_type=EventType.IP_UNBLOCKED, ip_address=ip
        ).first()
        assert log is not None
        assert "Support cleared ban" in log.description

    def test_automatic_block_expiry(self, app, db):
        """Expired block is automatically deactivated and logs IP_UNBLOCKED."""
        ip = "203.0.113.52"
        # Create an already-expired block
        past = datetime.now(timezone.utc) - timedelta(minutes=1)
        record = BlockedIP(
            ip_address=ip,
            reason="Expired block",
            expires_at=past,
            active=True,
        )
        db.session.add(record)
        db.session.commit()

        # is_ip_blocked should detect expiration, mark inactive, and return False
        blocked, _ = is_ip_blocked(ip)
        assert blocked is False

        # Confirm DB state updated
        refreshed = db.session.get(BlockedIP, record.id)
        assert refreshed.active is False

        # Confirm auto-unblock logged
        unblock_log = ActivityLog.query.filter_by(
            event_type=EventType.IP_UNBLOCKED, ip_address=ip
        ).first()
        assert unblock_log is not None
        assert "expired automatically" in unblock_log.description

    def test_get_active_blocks(self, app, db):
        ip1 = "203.0.113.60"
        ip2 = "203.0.113.61"
        block_ip(ip1, duration_minutes=20)
        block_ip(ip2, duration_minutes=20)

        active = get_active_blocks()
        active_ips = [b.ip_address for b in active]
        assert ip1 in active_ips
        assert ip2 in active_ips


# ─────────────────────────────────────────────────────────────────────────────
# 3. Middleware Enforcement Tests (403 Forbidden for Blocked IPs)
# ─────────────────────────────────────────────────────────────────────────────

class TestIPBlockingMiddleware:
    """Test request interception for blocked IPs."""

    def test_blocked_ip_receives_403(self, app, db):
        from app import create_app
        test_app = create_app(BaseConfig)

        with test_app.app_context():
            from extensions import db as _d
            _d.create_all()

            blocked_ip_addr = "198.51.100.99"
            block_ip(blocked_ip_addr, reason="Suspicious scanner", duration_minutes=30)

            with test_app.test_client() as c:
                # Request with simulated blocked IP in X-Forwarded-For
                r = c.get(
                    "/auth/login",
                    headers={"X-Forwarded-For": blocked_ip_addr},
                )
                assert r.status_code == 403
                data = r.get_json()
                assert data["blocked"] is True
                assert data["ip_address"] == blocked_ip_addr
                assert "temporarily blocked" in data["message"]

    def test_unblocked_ip_can_access_after_unblock(self, app, db):
        from app import create_app
        test_app = create_app(BaseConfig)

        with test_app.app_context():
            from extensions import db as _d
            _d.create_all()

            ip = "198.51.100.100"
            block_ip(ip, duration_minutes=30)

            with test_app.test_client() as c:
                # Initially 403
                r1 = c.get("/auth/login", headers={"X-Forwarded-For": ip})
                assert r1.status_code == 403

                # Unblock
                unblock_ip(ip)

                # Subsequent request allowed (200 OK)
                r2 = c.get("/auth/login", headers={"X-Forwarded-For": ip})
                assert r2.status_code == 200


# ─────────────────────────────────────────────────────────────────────────────
# 4. Rate Limiting Tests (429 Too Many Requests)
# ─────────────────────────────────────────────────────────────────────────────

class TestRateLimiting:
    """Test Flask-Limiter enforcement and violation activity logging."""

    def test_rate_limit_exceeded_returns_429_and_logs_event(self):
        from app import create_app

        class RateLimitTestConfig(BaseConfig):
            TESTING = True
            WTF_CSRF_ENABLED = False
            SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
            RATELIMIT_ENABLED = True
            RATELIMIT_STORAGE_URI = "memory://"
            RATELIMIT_DEFAULT = "100 per hour"

        rate_app = create_app(RateLimitTestConfig)
        with rate_app.app_context():
            from extensions import db as _d
            _d.create_all()

            with rate_app.test_client() as c:
                test_ip = "192.0.2.200"

                # Trigger registration limit (5 per minute)
                responses = []
                for i in range(7):
                    res = c.post(
                        "/auth/register",
                        data={
                            "username": f"user{i}",
                            "email": f"user{i}@example.com",
                            "password": "Pass@Word1",
                            "confirm_password": "Pass@Word1",
                        },
                        headers={"X-Forwarded-For": test_ip},
                    )
                    responses.append(res.status_code)

                # At least one request beyond the limit must return 429
                assert 429 in responses

                # Confirm RATE_LIMIT_EXCEEDED event logged
                violation_log = ActivityLog.query.filter_by(
                    event_type=EventType.RATE_LIMIT_EXCEEDED
                ).first()
                assert violation_log is not None
                assert violation_log.status == ActivityStatus.BLOCKED
                assert violation_log.risk_score == 30
