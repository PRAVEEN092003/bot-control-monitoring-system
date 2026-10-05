"""
forms/auth_forms.py — WTForms definitions for registration and login.

CSRF protection is inherited from FlaskForm (Flask-WTF).
All validation is server-side — frontend HTML5 attributes are
supplementary only.
"""

import re
from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    EmailField,
    PasswordField,
    StringField,
    SubmitField,
)
from wtforms.validators import (
    DataRequired,
    Email,
    EqualTo,
    Length,
    Regexp,
    ValidationError,
)


# ── Shared password strength validator ────────────────────────────────────────

def _validate_password_strength(form, field):
    """
    Enforce password complexity:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    password = field.data or ""
    errors = []

    if len(password) < 8:
        errors.append("at least 8 characters")
    if not re.search(r"[A-Z]", password):
        errors.append("one uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("one lowercase letter")
    if not re.search(r"\d", password):
        errors.append("one digit")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password):
        errors.append("one special character")

    if errors:
        raise ValidationError(
            "Password must contain: " + ", ".join(errors) + "."
        )


# ── Registration form ──────────────────────────────────────────────────────────

class RegistrationForm(FlaskForm):
    """New user sign-up form.  CSRF token included automatically."""

    username = StringField(
        "Username",
        validators=[
            DataRequired(message="Username is required."),
            Length(min=3, max=64, message="Username must be between 3 and 64 characters."),
            Regexp(
                r"^[A-Za-z0-9_.-]+$",
                message="Username may only contain letters, numbers, underscores, hyphens, and dots.",
            ),
        ],
        render_kw={"autocomplete": "username", "placeholder": "e.g. john_doe"},
    )

    email = EmailField(
        "Email Address",
        validators=[
            DataRequired(message="Email is required."),
            Email(message="Enter a valid email address.", check_deliverability=False),
            Length(max=120, message="Email must be 120 characters or fewer."),
        ],
        render_kw={"autocomplete": "email", "placeholder": "you@example.com"},
    )

    password = PasswordField(
        "Password",
        validators=[
            DataRequired(message="Password is required."),
            Length(max=128, message="Password must be 128 characters or fewer."),
            _validate_password_strength,
        ],
        render_kw={"autocomplete": "new-password", "placeholder": "Min 8 chars, mixed case, digit, symbol"},
    )

    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(message="Please confirm your password."),
            EqualTo("password", message="Passwords must match."),
        ],
        render_kw={"autocomplete": "new-password", "placeholder": "Repeat password"},
    )

    submit = SubmitField("Create Account")


# ── Login form ─────────────────────────────────────────────────────────────────

class LoginForm(FlaskForm):
    """User login form.  CSRF token included automatically."""

    email = EmailField(
        "Email Address",
        validators=[
            DataRequired(message="Email is required."),
            Email(message="Enter a valid email address.", check_deliverability=False),
        ],
        render_kw={"autocomplete": "email", "placeholder": "you@example.com"},
    )


    password = PasswordField(
        "Password",
        validators=[
            DataRequired(message="Password is required."),
        ],
        render_kw={"autocomplete": "current-password", "placeholder": "Your password"},
    )

    captcha_input = StringField(
        "Verification Code",
        validators=[
            Length(max=32, message="CAPTCHA answer must be between 1 and 32 characters."),
        ],
        render_kw={
            "placeholder": "Enter code here...",
            "autocomplete": "off",
            "autocorrect": "off",
            "autocapitalize": "off",
            "spellcheck": "false",
        },
    )

    remember_me = BooleanField("Remember me")

    submit = SubmitField("Sign In")
