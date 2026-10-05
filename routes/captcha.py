"""
routes/captcha.py — CAPTCHA challenge, verification, and regeneration routes.

Endpoints
---------
GET/POST  /captcha/challenge  — Display & verify dedicated CAPTCHA challenge
GET/POST  /captcha/           — Alias for /captcha/challenge
GET       /captcha/refresh    — Regenerate a fresh CAPTCHA challenge
GET       /captcha/image      — Stream current CAPTCHA as a PNG image
GET       /captcha/ping       — Blueprint health-check
"""

import logging
from urllib.parse import urljoin, urlparse

from flask import (
    Blueprint,
    Response,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user

from extensions import limiter
from forms.captcha_forms import CaptchaForm
from services.captcha_service import (
    create_captcha_session,
    generate_captcha_base64,
    generate_captcha_image,
    is_captcha_expired,
    verify_captcha,
)

logger = logging.getLogger(__name__)

captcha_bp = Blueprint("captcha", __name__, url_prefix="/captcha")


def _is_safe_url(target: str | None) -> bool:
    """Ensure redirect targets belong to the same host."""
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


@captcha_bp.route("/ping")
def ping():
    """Health-check endpoint."""
    return jsonify({"status": "captcha blueprint active", "phase": 3})


@captcha_bp.route("/", methods=["GET", "POST"])
@captcha_bp.route("/challenge", methods=["GET", "POST"])
@limiter.limit("10 per minute; 30 per hour")
def challenge():

    """
    Dedicated CAPTCHA challenge page.

    GET:
      Ensures an active, unexpired challenge is in the session and renders the page.
    POST:
      Validates the CSRF token and user-submitted answer.
      On success: redirects to `next` or dashboard.
      On failure: generates a fresh challenge and redisplays with an error.
    """
    form = CaptchaForm()
    next_url = request.args.get("next") or request.form.get("next")

    if request.method == "GET":
        # Create a challenge if absent or expired
        if "captcha_text" not in session or is_captcha_expired():
            create_captcha_session()

        captcha_image = generate_captcha_base64(session["captcha_text"])
        return render_template(
            "captcha.html",
            form=form,
            captcha_image=captcha_image,
        )

    # POST verification
    if form.validate_on_submit():
        user_input = form.captcha_input.data
        user_id = current_user.id if current_user.is_authenticated else None

        is_valid, message = verify_captcha(
            user_input=user_input,
            user_id=user_id,
        )

        if is_valid:
            flash("Security check passed successfully!", "success")
            if next_url and _is_safe_url(next_url):
                return redirect(next_url)
            if current_user.is_authenticated:
                return redirect(url_for("user.dashboard"))
            return redirect(url_for("index"))

        # Verification failed — regenerate immediately for next try
        flash(message, "danger")
        _, new_image = create_captcha_session()
        form.captcha_input.data = ""
        return render_template(
            "captcha.html",
            form=form,
            captcha_image=new_image,
        )

    # CSRF or form validation error: regenerate challenge and redisplay
    _, new_image = create_captcha_session()
    return render_template(
        "captcha.html",
        form=form,
        captcha_image=new_image,
    )



@captcha_bp.route("/refresh", methods=["GET", "POST"])
@limiter.limit("20 per minute")
def refresh():

    """
    Regenerate a new CAPTCHA challenge for the user.

    Returns JSON if requested via AJAX / API, otherwise redirects back to challenge.
    """
    _, image_uri = create_captcha_session()
    next_url = request.args.get("next")

    if (
        request.headers.get("Accept") == "application/json"
        or request.args.get("format") == "json"
    ):
        return jsonify({
            "success": True,
            "captcha_image": image_uri,
            "message": "CAPTCHA refreshed successfully.",
        })

    flash("A new CAPTCHA challenge has been loaded.", "info")
    return redirect(url_for("captcha.challenge", next=next_url))


@captcha_bp.route("/image")
def image():
    """Serve the active CAPTCHA challenge as a standalone PNG image."""
    captcha_text = session.get("captcha_text")
    if not captcha_text or is_captcha_expired():
        captcha_text, _ = create_captcha_session()

    img_bytes = generate_captcha_image(captcha_text)
    return Response(
        img_bytes,
        mimetype="image/png",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )
