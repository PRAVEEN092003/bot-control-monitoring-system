"""
forms/captcha_forms.py — WTForms definition for CAPTCHA verification.

Inherits CSRF protection from FlaskForm (Flask-WTF).
"""

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length


class CaptchaForm(FlaskForm):
    """Form for submitting a CAPTCHA challenge answer."""

    captcha_input = StringField(
        "Enter Verification Code",
        validators=[
            DataRequired(message="Please enter the CAPTCHA text shown in the image."),
            Length(min=1, max=32, message="CAPTCHA answer must be between 1 and 32 characters."),
        ],
        render_kw={
            "placeholder": "Enter code here...",
            "autocomplete": "off",
            "autocorrect": "off",
            "autocapitalize": "off",
            "spellcheck": "false",
        },
    )

    submit = SubmitField("Verify & Continue")
