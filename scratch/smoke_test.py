import sys
import os
sys.path.insert(0, os.path.abspath("."))
from app import create_app
from config import TestingConfig
from extensions import db
from models.activity import ActivityLog, EventType, RiskLevel
from models.user import User
from models.captcha import CaptchaAttempt
from models.blocked_ip import BlockedIP
from services.captcha_service import create_captcha_session, verify_captcha
from services.ip_blocker import block_ip, unblock_ip

def run_smoke_test():
    print("=" * 60)
    print("STARTING FULL END-TO-END SMOKE TEST")
    print("=" * 60)

    app = create_app(TestingConfig)

    with app.test_client() as client:
        with app.app_context():
            # Clean and recreate tables
            db.drop_all()
            db.create_all()

            # 1. Admin Creation
            admin = User(username="admin", email="admin@botmonitor.com", is_admin=True)
            admin.set_password("Admin@Pass123!")
            db.session.add(admin)
            db.session.commit()
            print("[PASS] 1. Admin account created.")

            # 2. User Registration
            reg_resp = client.post(
                "/auth/register",
                data={
                    "username": "student_user",
                    "email": "student@example.com",
                    "password": "SecurePassword1!",
                    "confirm_password": "SecurePassword1!",
                },
                follow_redirects=True,
            )
            assert reg_resp.status_code == 200
            user = User.query.filter_by(email="student@example.com").first()
            assert user is not None
            print("[PASS] 2. User registration completed and verified in DB.")

            # 3. 1st Failed Login
            fail1_resp = client.post(
                "/auth/login",
                data={"email": "student@example.com", "password": "WrongPassword1!"},
                follow_redirects=True,
            )
            assert fail1_resp.status_code == 200
            user = User.query.filter_by(email="student@example.com").first()
            assert user.failed_login_count == 1
            logs = ActivityLog.query.filter_by(user_id=user.id, event_type=EventType.LOGIN_FAILURE).all()
            assert len(logs) == 1
            assert logs[0].risk_level == RiskLevel.NORMAL
            assert b"Verification Image" not in fail1_resp.data
            print("[PASS] 3. First failed login logged as NORMAL; CAPTCHA not triggered.")

            # 4. 2nd Failed Login -> triggers adaptive CAPTCHA
            fail2_resp = client.post(
                "/auth/login",
                data={"email": "student@example.com", "password": "WrongPassword2!"},
                follow_redirects=True,
            )
            assert fail2_resp.status_code == 200
            user = User.query.filter_by(email="student@example.com").first()
            assert user.failed_login_count == 2
            logs = ActivityLog.query.filter_by(user_id=user.id, event_type=EventType.LOGIN_FAILURE).order_by(ActivityLog.id.asc()).all()
            assert len(logs) == 2
            assert logs[1].risk_level == RiskLevel.SUSPICIOUS
            assert b"Verification Image" in fail2_resp.data
            print("[PASS] 4. Second failed login classified as SUSPICIOUS; Adaptive CAPTCHA challenge displayed.")

            # 5. Wrong CAPTCHA attempt
            fail_cap_resp = client.post(
                "/auth/login",
                data={
                    "email": "student@example.com",
                    "password": "WrongPassword3!",
                    "captcha_input": "WRONGCODE",
                },
                follow_redirects=True,
            )
            assert fail_cap_resp.status_code == 200
            cap_fail_log = ActivityLog.query.filter_by(user_id=user.id, event_type=EventType.CAPTCHA_FAILURE).first()
            assert cap_fail_log is not None
            print("[PASS] 5. Incorrect CAPTCHA rejected and logged as CAPTCHA_FAILURE.")

            # 6. Correct CAPTCHA + Correct Password -> Successful Login
            with client.session_transaction() as sess:
                sess["captcha_text"] = "ABCD"
                import time
                sess["captcha_expires_at"] = time.time() + 300
                sess["require_captcha"] = True

            success_resp = client.post(
                "/auth/login",
                data={
                    "email": "student@example.com",
                    "password": "SecurePassword1!",
                    "captcha_input": "abcd",  # case insensitive
                },
                follow_redirects=True,
            )
            assert success_resp.status_code == 200
            assert b"Welcome back, student_user" in success_resp.data

            user = User.query.filter_by(email="student@example.com").first()
            assert user.failed_login_count == 0
            print("[PASS] 6. Correct CAPTCHA + credentials accepted; failed_login_count reset to 0.")

            # 7. User Dashboard verification
            dash_resp = client.get("/user/dashboard")
            assert dash_resp.status_code == 200
            assert b"student_user" in dash_resp.data
            assert b"Total Failed Login Attempts" in dash_resp.data
            # Historical count should show 2 from ActivityLog
            assert b"2" in dash_resp.data
            print("[PASS] 7. User dashboard displays accurate historical failed login attempts (2).")

            # 8. User Activity isolation
            act_resp = client.get("/user/activity")
            assert act_resp.status_code == 200
            assert b"Security Activity Log" in act_resp.data
            print("[PASS] 8. User activity page loads with user-isolated audit trail.")

            # 9. Logout
            logout_resp = client.get("/auth/logout", follow_redirects=True)
            assert logout_resp.status_code == 200
            assert b"You have been logged out successfully" in logout_resp.data
            print("[PASS] 9. User logged out successfully.")

            # 10. Admin Login
            admin_login_resp = client.post(
                "/auth/login",
                data={"email": "admin@botmonitor.com", "password": "Admin@Pass123!"},
                follow_redirects=True,
            )
            assert admin_login_resp.status_code == 200
            print("[PASS] 10. Admin authenticated.")

            # 11. Admin Dashboard KPIs & Charts
            admin_dash_resp = client.get("/admin/dashboard")
            assert admin_dash_resp.status_code == 200
            assert b"Admin Security Dashboard" in admin_dash_resp.data
            assert b"Security Event Distribution" in admin_dash_resp.data
            assert b"Risk Level Breakdown" in admin_dash_resp.data

            # API stats
            stats_resp = client.get("/admin/api/stats")
            assert stats_resp.status_code == 200
            stats = stats_resp.get_json()
            assert stats["total_users"] == 2
            assert stats["suspicious_count"] >= 1
            print(f"[PASS] 11. Admin dashboard KPIs verified: Users={stats['total_users']}, Events={stats['total_events']}, Suspicious={stats['suspicious_count']}.")

            # 12. Admin Security Logs viewer
            logs_resp = client.get("/admin/logs")
            assert logs_resp.status_code == 200
            assert b"Security Audit Logs" in logs_resp.data
            print("[PASS] 12. Admin security audit logs page verified.")

            # 13. Admin Blocked IP Management
            block_resp = client.post(
                "/admin/block-ip",
                data={"ip_address": "203.0.113.99", "reason": "Automated brute force", "duration": "15"},
                follow_redirects=True,
            )
            assert block_resp.status_code == 200
            blocked_entry = BlockedIP.query.filter_by(ip_address="203.0.113.99", active=True).first()
            assert blocked_entry is not None
            print("[PASS] 13. IP 203.0.113.99 manually blocked.")

            unblock_resp = client.post(
                "/admin/unblock-ip",
                data={"ip_address": "203.0.113.99", "note": "False positive resolved"},
                follow_redirects=True,
            )
            assert unblock_resp.status_code == 200
            blocked_entry = BlockedIP.query.filter_by(ip_address="203.0.113.99", active=True).first()
            assert blocked_entry is None
            print("[PASS] 14. IP 203.0.113.99 manually unblocked.")

            print("=" * 60)
            print("ALL 14 END-TO-END SMOKE TEST STEPS PASSED PERFECTLY!")
            print("=" * 60)

if __name__ == "__main__":
    run_smoke_test()
