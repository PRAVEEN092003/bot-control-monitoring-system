"""
services/ip_blocker.py — Temporary IP blocking management and enforcement.

Features:
- Temporary IP blocking with configurable expiration (IP_BLOCK_DURATION_MINUTES).
- Automatic block expiration evaluation (lazy unblocking on request).
- Manual and programmatic unblocking.
- Audit event logging for all IP_BLOCKED and IP_UNBLOCKED events.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from typing import List, Optional, Tuple

from flask import current_app

from extensions import db
from models.activity import ActivityStatus, EventType
from models.blocked_ip import BlockedIP
from services.monitoring import log_event

logger = logging.getLogger(__name__)


def block_ip(
    ip_address: str,
    reason: str = "High risk automated activity",
    duration_minutes: Optional[int] = None,
    risk_score: int = 70,
) -> BlockedIP:
    """
    Temporarily block an IP address.

    Parameters
    ----------
    ip_address       : Target IP to block.
    reason           : Human-readable explanation.
    duration_minutes : Block duration in minutes (defaults to config IP_BLOCK_DURATION_MINUTES).
    risk_score       : Associated risk score (default 70).
    """
    if duration_minutes is None:
        try:
            duration_minutes = int(
                current_app.config.get("IP_BLOCK_DURATION_MINUTES", 30)
            )
        except RuntimeError:
            duration_minutes = 30

    expires_at = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)

    # Check if an active block already exists
    existing = BlockedIP.query.filter_by(ip_address=ip_address, active=True).first()
    if existing:
        existing.expires_at = expires_at
        existing.reason = reason
        existing.risk_score = max(existing.risk_score, risk_score)
        block_record = existing
    else:
        block_record = BlockedIP(
            ip_address=ip_address,
            reason=reason,
            risk_score=risk_score,
            expires_at=expires_at,
            active=True,
        )
        db.session.add(block_record)

    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.error(f"Failed to persist BlockedIP for {ip_address}: {exc}")

    # Audit log
    log_event(
        event_type=EventType.IP_BLOCKED,
        description=f"IP '{ip_address}' temporarily blocked for {duration_minutes}m: {reason}.",
        ip_address=ip_address,
        risk_score=risk_score,
        status=ActivityStatus.BLOCKED,
    )
    logger.warning(
        f"[IP_BLOCK] Blocked IP {ip_address} until {expires_at.isoformat()} | Reason: {reason}"
    )
    return block_record


def unblock_ip(
    ip_address: str,
    admin_note: str = "Manually unblocked",
) -> bool:
    """
    Manually deactivate all active blocks for a given IP address.

    Returns True if an active block was deactivated, False otherwise.
    """
    active_blocks = BlockedIP.query.filter_by(ip_address=ip_address, active=True).all()
    if not active_blocks:
        return False

    for b in active_blocks:
        b.deactivate(note=admin_note)

    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.error(f"Failed to unblock IP {ip_address}: {exc}")
        return False

    # Audit log
    log_event(
        event_type=EventType.IP_UNBLOCKED,
        description=f"IP '{ip_address}' unblocked: {admin_note}.",
        ip_address=ip_address,
        risk_score=0,
        status=ActivityStatus.SUCCESS,
    )
    logger.info(f"[IP_UNBLOCK] Unblocked IP {ip_address} | Note: {admin_note}")
    return True


def is_ip_blocked(ip_address: str) -> Tuple[bool, Optional[BlockedIP]]:
    """
    Check if an IP address is currently under an active block.

    If the block has passed its expiration time, it is automatically marked
    inactive and an IP_UNBLOCKED audit log is written.

    Returns
    -------
    (is_blocked, active_block_record_or_None)
    """
    if not ip_address or ip_address in ("127.0.0.1", "localhost", "unknown"):
        # Still check DB for exact match even on localhost during tests if explicitly added
        pass

    try:
        active_block = (
            BlockedIP.query
            .filter_by(ip_address=ip_address, active=True)
            .order_by(BlockedIP.expires_at.desc())
            .first()
        )
    except Exception:
        return False, None

    if not active_block:
        return False, None

    # Check if expired
    if active_block.is_expired:
        active_block.active = False
        try:
            db.session.commit()
            log_event(
                event_type=EventType.IP_UNBLOCKED,
                description=f"Temporary block on IP '{ip_address}' expired automatically.",
                ip_address=ip_address,
                risk_score=0,
                status=ActivityStatus.SUCCESS,
            )
            logger.info(f"[IP_UNBLOCK] Block for {ip_address} expired automatically.")
        except Exception as exc:
            db.session.rollback()
            logger.error(f"Failed to auto-expire block for {ip_address}: {exc}")
        return False, None

    return True, active_block


def get_active_blocks() -> List[BlockedIP]:
    """Return all currently active and unexpired BlockedIP records."""
    active_records = BlockedIP.query.filter_by(active=True).all()
    return [b for b in active_records if not b.is_expired]

