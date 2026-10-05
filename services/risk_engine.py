"""
services/risk_engine.py — Risk scoring engine and classification.

Risk weights per specification:
- Failed login: +20
- CAPTCHA failure: +25
- Excessive activity: +30
- Repeated suspicious activity: +25

Risk levels:
- 0–30:   NORMAL
- 31–60:  SUSPICIOUS
- 61–100: HIGH_RISK
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple
from models.activity import RiskLevel

# ── Risk score weights ─────────────────────────────────────────────────────────
WEIGHT_FAILED_LOGIN = 20
WEIGHT_CAPTCHA_FAILURE = 25
WEIGHT_EXCESSIVE_ACTIVITY = 30
WEIGHT_REPEATED_SUSPICIOUS = 25

# Threshold boundaries
THRESHOLD_NORMAL_MAX = 30
THRESHOLD_SUSPICIOUS_MAX = 60


def clamp_score(score: int) -> int:
    """Ensure risk score stays within [0, 100]."""
    return max(0, min(100, int(score)))


def compute_risk_level(score: int) -> str:
    """
    Map a numeric risk score (0–100) to its corresponding RiskLevel constant.

    0–30   -> NORMAL
    31–60  -> SUSPICIOUS
    61–100 -> HIGH_RISK
    """
    clamped = clamp_score(score)
    if clamped > THRESHOLD_SUSPICIOUS_MAX:
        return RiskLevel.HIGH_RISK
    if clamped > THRESHOLD_NORMAL_MAX:
        return RiskLevel.SUSPICIOUS
    return RiskLevel.NORMAL


def calculate_risk_score(
    failed_logins: int = 0,
    captcha_failures: int = 0,
    has_excessive_activity: bool = False,
    has_repeated_suspicious: bool = False,
    base_score: int = 0,
) -> Tuple[int, str, Dict[str, int]]:
    """
    Compute aggregate risk score and level from detected behavioral components.

    Parameters
    ----------
    failed_logins           : Number of failed logins in observation window.
    captcha_failures        : Number of failed CAPTCHAs in observation window.
    has_excessive_activity  : Whether request volume exceeded limit (+30).
    has_repeated_suspicious : Whether rapid bursts or repeated anomalies occurred (+25).
    base_score              : Initial score baseline (default 0).

    Returns
    -------
    (total_score, risk_level, breakdown_dict)
    """
    breakdown = {}

    score = base_score
    if base_score > 0:
        breakdown["base"] = base_score

    if failed_logins > 0:
        contrib = failed_logins * WEIGHT_FAILED_LOGIN
        score += contrib
        breakdown["failed_logins"] = contrib

    if captcha_failures > 0:
        contrib = captcha_failures * WEIGHT_CAPTCHA_FAILURE
        score += contrib
        breakdown["captcha_failures"] = contrib

    if has_excessive_activity:
        score += WEIGHT_EXCESSIVE_ACTIVITY
        breakdown["excessive_activity"] = WEIGHT_EXCESSIVE_ACTIVITY

    if has_repeated_suspicious:
        score += WEIGHT_REPEATED_SUSPICIOUS
        breakdown["repeated_suspicious"] = WEIGHT_REPEATED_SUSPICIOUS

    final_score = clamp_score(score)
    level = compute_risk_level(final_score)

    return final_score, level, breakdown
