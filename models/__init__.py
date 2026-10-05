# models/__init__.py
# Import all models so SQLAlchemy can discover them when create_all() is called.

from .user import User
from .activity import ActivityLog
from .captcha import CaptchaAttempt
from .blocked_ip import BlockedIP

__all__ = ["User", "ActivityLog", "CaptchaAttempt", "BlockedIP"]
