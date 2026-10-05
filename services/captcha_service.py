"""
services/captcha_service.py — CAPTCHA generation, storage, and verification service.

Key security design:
1. CAPTCHA text is randomly generated from an unambiguous alphanumeric alphabet.
2. Raw answer text is stored ONLY in the encrypted client session (never in the database).
3. Every CAPTCHA token has a strict expiry timestamp (configured via CAPTCHA_EXPIRY_SECONDS).
4. Tokens are strictly single-use: verified sessions are cleared immediately to prevent replay attacks.
5. Every challenge outcome (success, failure, expired) creates an immutable CaptchaAttempt audit
   record and triggers security event logging in ActivityLog.
"""

from __future__ import annotations

import base64
import io
import logging
import math
import random
import secrets
import string
import time
from typing import Optional, Tuple

from flask import current_app, request, session
from PIL import Image, ImageDraw, ImageFilter, ImageFont

from extensions import db
from models.captcha import CaptchaAttempt
from services.monitoring import log_captcha_failure, log_captcha_success

logger = logging.getLogger(__name__)

# Character set excluding easily ambiguous glyphs (0/O, 1/I/l, 8/B in some fonts)
CAPTCHA_CHARSET = "23456789ACDEFGHJKLMNPQRSTUVWXYZ"


def generate_captcha_text(length: Optional[int] = None) -> str:
    """
    Generate a cryptographically secure random alphanumeric string.

    Parameters
    ----------
    length : int, optional
        Number of characters. Defaults to CAPTCHA_LENGTH from app config.
    """
    if length is None:
        try:
            length = int(current_app.config.get("CAPTCHA_LENGTH", 6))
        except RuntimeError:
            length = 6
    return "".join(secrets.choice(CAPTCHA_CHARSET) for _ in range(length))


def generate_captcha_image(
    text: str,
    width: int = 240,
    height: int = 80,
) -> bytes:
    """
    Render a visual CAPTCHA image with distortion, noise, and styling.

    Parameters
    ----------
    text   : str
        The CAPTCHA text to draw.
    width  : int
        Image width in pixels (default 240).
    height : int
        Image height in pixels (default 80).

    Returns
    -------
    bytes
        Raw PNG-encoded image bytes.
    """
    # Create dark background matching the application's theme (#0f172a)
    bg_color = (15, 23, 42)
    image = Image.new("RGBA", (width, height), bg_color + (255,))
    draw = ImageDraw.Draw(image)

    # 1. Background noise lines and grid
    for _ in range(6):
        x1, y1 = random.randint(0, width), random.randint(0, height)
        x2, y2 = random.randint(0, width), random.randint(0, height)
        line_color = random.choice([
            (30, 41, 59, 120),
            (51, 65, 85, 120),
            (56, 189, 248, 60),
            (99, 102, 241, 60),
        ])
        draw.line([(x1, y1), (x2, y2)], fill=line_color, width=random.randint(1, 2))

    # 2. Background noise dots
    for _ in range(120):
        nx = random.randint(0, width - 1)
        ny = random.randint(0, height - 1)
        dot_color = random.choice([
            (56, 189, 248, 100),
            (168, 85, 247, 100),
            (34, 197, 94, 80),
            (245, 158, 11, 80),
        ])
        draw.point((nx, ny), fill=dot_color)

    # 3. Choose font
    try:
        font = ImageFont.load_default(size=32)
    except TypeError:
        font = ImageFont.load_default()

    # Character colors (high-contrast vibrant cybersecurity palette)
    text_colors = [
        (56, 189, 248),   # Cyan / sky
        (129, 140, 248),  # Indigo
        (52, 211, 153),   # Emerald
        (251, 191, 36),   # Amber
        (244, 114, 182),  # Pink
        (192, 132, 252),  # Purple
        (248, 250, 252),  # Bright white
    ]

    # 4. Draw each character onto a separate rotated layer
    char_count = len(text)
    slot_width = (width - 30) // max(char_count, 1)

    for i, char in enumerate(text):
        char_img = Image.new("RGBA", (50, 60), (0, 0, 0, 0))
        char_draw = ImageDraw.Draw(char_img)
        char_color = random.choice(text_colors)

        # Shadow
        char_draw.text((12, 10), char, fill=(0, 0, 0, 180), font=font)
        # Main text
        char_draw.text((10, 8), char, fill=char_color + (255,), font=font)

        # Random rotation (-25° to +25°)
        angle = random.uniform(-25, 25)
        rotated_char = char_img.rotate(angle, resample=Image.Resampling.BILINEAR, expand=True)

        # Paste onto main canvas
        base_x = 15 + i * slot_width + random.randint(-4, 4)
        base_y = (height - rotated_char.height) // 2 + random.randint(-4, 4)
        image.paste(rotated_char, (max(0, base_x), max(0, base_y)), rotated_char)

    # 5. Foreground interference wavy lines
    for _ in range(3):
        points = []
        freq = random.uniform(0.02, 0.05)
        phase = random.uniform(0, 2 * math.pi)
        amplitude = random.uniform(5, 12)
        start_y = random.randint(20, height - 20)
        for x in range(0, width, 4):
            y = start_y + int(amplitude * math.sin(freq * x + phase))
            points.append((x, y))
        line_color = random.choice([
            (56, 189, 248, 140),
            (168, 85, 247, 140),
            (255, 255, 255, 100),
        ])
        draw.line(points, fill=line_color, width=2)

    # Convert to RGB and encode to PNG bytes
    rgb_image = Image.new("RGB", (width, height), bg_color)
    rgb_image.paste(image, mask=image.split()[3])

    buffer = io.BytesIO()
    rgb_image.save(buffer, format="PNG", optimize=True)
    return buffer.getvalue()


def generate_captcha_base64(text: str) -> str:
    """Generate image and return data URI string for direct HTML embedding."""
    raw_bytes = generate_captcha_image(text)
    encoded = base64.b64encode(raw_bytes).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def create_captcha_session(
    length: Optional[int] = None,
    expiry_seconds: Optional[int] = None,
) -> Tuple[str, str]:
    """
    Generate a new CAPTCHA, update the Flask session, and return (text, base64_image).

    Session keys written:
    - 'captcha_text'       : Plaintext answer stored in encrypted session cookie (~6 bytes)
    - 'captcha_expires_at' : Unix timestamp after which the challenge is invalid (~10 bytes)
    """
    text = generate_captcha_text(length)
    if expiry_seconds is None:
        try:
            expiry_seconds = int(current_app.config.get("CAPTCHA_EXPIRY_SECONDS", 120))
        except RuntimeError:
            expiry_seconds = 120

    expires_at = time.time() + expiry_seconds

    session["captcha_text"] = text.upper()
    session["captcha_expires_at"] = expires_at

    image_uri = generate_captcha_base64(text)
    logger.debug(f"Created new CAPTCHA session (expires in {expiry_seconds}s)")
    return text, image_uri


def is_captcha_expired() -> bool:
    """Check if the currently stored session CAPTCHA has exceeded its lifetime."""
    expires_at = session.get("captcha_expires_at")
    if not expires_at:
        return True
    return time.time() > float(expires_at)


def clear_captcha_session() -> None:
    """Clear all CAPTCHA-related state from the session."""
    session.pop("captcha_text", None)
    session.pop("captcha_expires_at", None)



def _record_attempt(
    success: bool,
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> CaptchaAttempt:
    """Persist a CaptchaAttempt row to the database."""
    if ip_address is None:
        try:
            from services.monitoring import _get_client_ip
            ip_address = _get_client_ip()
        except RuntimeError:
            ip_address = "unknown"

    if user_agent is None:
        try:
            user_agent = request.headers.get("User-Agent", "")[:512]
        except RuntimeError:
            user_agent = None

    attempt = CaptchaAttempt(
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        success=success,
    )
    db.session.add(attempt)
    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.error(f"Failed to record CaptchaAttempt: {exc}", exc_info=True)
    return attempt


def verify_captcha(
    user_input: str,
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Validate a user-submitted CAPTCHA against the active session token.

    Rules:
    - If no challenge exists in session: fail + record attempt + log failure.
    - If challenge has expired: fail + record attempt + log failure + clear session.
    - If input does not match: fail + record attempt + log failure + clear session.
    - If input matches: success + record attempt + log success + clear session.

    Returns
    -------
    (bool, str)
        Tuple of (is_valid, user_friendly_message)
    """
    expected_text = session.get("captcha_text")
    expires_at = session.get("captcha_expires_at")

    # 1. Check for missing challenge
    if not expected_text or not expires_at:
        _record_attempt(
            success=False,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        log_captcha_failure(
            user_id=user_id,
            reason="No active CAPTCHA session",
            ip_address=ip_address,
        )
        return False, "No active CAPTCHA challenge found. A new challenge has been generated."

    # 2. Check for expired challenge
    if time.time() > float(expires_at):
        clear_captcha_session()
        _record_attempt(
            success=False,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        log_captcha_failure(
            user_id=user_id,
            reason="CAPTCHA challenge expired",
            ip_address=ip_address,
        )
        return False, "The CAPTCHA code has expired. Please solve the new challenge."

    # 3. Always clear the challenge on verification to enforce single-use
    clear_captcha_session()

    # 4. Compare submission (case-insensitive)
    cleaned_input = (user_input or "").strip().upper()
    if cleaned_input and cleaned_input == expected_text.upper():
        _record_attempt(
            success=True,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        log_captcha_success(
            user_id=user_id,
            ip_address=ip_address,
        )
        session["captcha_verified"] = True
        return True, "CAPTCHA verification successful."

    # 5. Mismatched answer
    _record_attempt(
        success=False,
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    log_captcha_failure(
        user_id=user_id,
        reason="Incorrect answer submitted",
        ip_address=ip_address,
    )
    return False, "Incorrect CAPTCHA answer. Please try again."
