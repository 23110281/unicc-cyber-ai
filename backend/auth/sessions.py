"""
Session control (Team 4)

A login pass (JWT) normally stays valid until it expires (60 minutes), even after
logging out - the server keeps no list of passes. This module adds two checks so
sessions really end when they should:

- Logging out puts that pass's unique ID ("jti") on a revoked list.
- Resetting a user's password ends ALL of that user's sessions: passes issued
  before the reset are refused (useful if a password or a pass was leaked).

Both lists are stored in the database, so they survive a server restart.
This module needs no JWT secret, so command-line tools can use it too.
"""

import datetime
from typing import Optional

from sqlalchemy.orm import Session

from backend.models import RevokedToken, SessionReset, utc_now


class SessionEndedError(Exception):
    """The pass was valid once, but its session has been ended."""


def _to_epoch(naive_utc: datetime.datetime) -> float:
    return naive_utc.replace(tzinfo=datetime.timezone.utc).timestamp()


def _from_epoch(seconds: float) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).replace(tzinfo=None)


def check_session(db: Session, claims: dict) -> None:
    """Raise SessionEndedError if this (already signature-checked) pass must no longer be accepted."""
    jti: Optional[str] = claims.get("jti")
    issued_at = claims.get("iat")
    if not jti or issued_at is None:
        raise SessionEndedError("This login pass is from an older version. Please log in again.")

    if db.get(RevokedToken, jti):
        raise SessionEndedError("This session was logged out. Please log in again.")

    reset = db.get(SessionReset, str(claims.get("id")))
    if reset and float(issued_at) < _to_epoch(reset.not_before):
        raise SessionEndedError("This session was ended (password changed). Please log in again.")


def revoke_token(db: Session, claims: dict) -> None:
    """Log out one session: its pass is refused from now on."""
    jti = claims.get("jti")
    if not jti:
        return
    expires_at = _from_epoch(float(claims["exp"])) if claims.get("exp") else utc_now()
    if not db.get(RevokedToken, jti):
        db.add(RevokedToken(jti=jti, expires_at=expires_at))
    # Tidy up: passes that have expired anyway don't need to stay on the list.
    db.query(RevokedToken).filter(RevokedToken.expires_at < utc_now()).delete()
    db.commit()


def end_all_sessions(db: Session, user_id: str) -> None:
    """Refuse every pass this user received before now (all browsers, all computers)."""
    reset = db.get(SessionReset, str(user_id))
    if reset:
        reset.not_before = utc_now()
    else:
        db.add(SessionReset(user_id=str(user_id), not_before=utc_now()))
    db.commit()
