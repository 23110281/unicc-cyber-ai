"""
Authentication Service (Team 4)
Handles JWT creation, httpOnly cookies, and defines an abstract IdentityProvider.
"""
from abc import ABC, abstractmethod
from typing import Optional, Dict, List
from datetime import datetime, timedelta, timezone
import logging
import os
import secrets
import jwt
from sqlalchemy.orm import Session
from backend.models import User
from backend.config import get_int
from backend.auth.passwords import verify_password

# Secrets that were once written in this project's public code. Anyone can read
# them on GitHub, so they must never be accepted as the real key.
_KNOWN_PUBLIC_SECRETS = {"super-secret-dev-key-that-is-at-least-32-bytes-long!"}


def _load_jwt_secret() -> str:
    """
    Return the key used to sign login passes (JWTs).

    Anyone who knows this key can create a pass for any user with any role,
    including admin. So it must never be written in the code.

    - If the JWT_SECRET environment variable is set, it is used. It must be at
      least 32 characters and must not be one of the old public values.
    - If it is not set, a random key is created for this run only. That is safe,
      but everyone is logged out whenever the server restarts.
      Real deployments must always set JWT_SECRET.
    """
    secret = os.environ.get("JWT_SECRET", "")
    if secret:
        if secret in _KNOWN_PUBLIC_SECRETS:
            raise RuntimeError("JWT_SECRET is set to a value that is published in the project's code. Choose a new random value.")
        if len(secret) < 32:
            raise RuntimeError("JWT_SECRET must be at least 32 characters long.")
        return secret

    logging.getLogger("uvicorn.error").warning(
        "JWT_SECRET is not set: using a temporary random key. "
        "Everyone will be logged out when the server restarts. "
        "Set JWT_SECRET for real deployments."
    )
    return secrets.token_urlsafe(48)


JWT_SECRET = _load_jwt_secret()
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = get_int("SESSION_MINUTES", 60)   # how long a login lasts

class IdentityProvider(ABC):
    @abstractmethod
    def authenticate(self, username: str, password: str) -> Optional[Dict[str, str]]:
        pass

class DBUserStore(IdentityProvider):
    """Database-backed user store for authenticating against the SQLite DB."""
    
    def __init__(self, db: Session):
        self.db = db
        
    def authenticate(self, username: str, password: str) -> Optional[Dict[str, str]]:
        user = self.db.query(User).filter(User.username == username).first()
        if user and verify_password(password, user.hashed_password):
            return {"id": str(user.id), "username": user.username, "role": user.role}
        return None

def create_jwt_token(data: dict) -> str:
    """Create a signed login pass (JWT)."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    to_encode.update({
        "exp": now + timedelta(minutes=TOKEN_EXPIRE_MINUTES),
        "iat": now.timestamp(),            # exact issue time (used to end sessions after a password reset)
        "jti": secrets.token_hex(16),      # unique ID of this pass (used to log out just this session)
    })
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

class UnauthorizedError(Exception): pass
class ForbiddenError(Exception): pass

def require_role(token: str, required_roles: List[str]) -> dict:
    """
    Decodes the token and verifies the role is in required_roles.
    Raises UnauthorizedError if invalid, ForbiddenError if role mismatch.
    Returns decoded user dict if successful.
    """
    if not token:
        raise UnauthorizedError("Missing token")
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if decoded.get("role") not in required_roles:
            raise ForbiddenError(f"Your role ({decoded.get('role')}) is not allowed to do this.")
        return decoded
    except jwt.ExpiredSignatureError:
        raise UnauthorizedError("Token expired")
    except jwt.InvalidTokenError:
        raise UnauthorizedError("Invalid token")
