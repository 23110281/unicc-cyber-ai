"""
Authentication Service (Team 4)
Handles JWT creation, httpOnly cookies, and defines an abstract IdentityProvider.
"""
from abc import ABC, abstractmethod
from typing import Optional, Dict, List
from datetime import datetime, timedelta
import os
import jwt
import bcrypt
from sqlalchemy.orm import Session
from backend.models import User

# Load secure 32+ byte secret from environment or use a secure fallback
JWT_SECRET = os.environ.get("JWT_SECRET", "super-secret-dev-key-that-is-at-least-32-bytes-long!")
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

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
    """Create a signed JWT token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
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
            raise ForbiddenError(f"Requires one of roles: {required_roles}")
        return decoded
    except jwt.ExpiredSignatureError:
        raise UnauthorizedError("Token expired")
    except jwt.InvalidTokenError:
        raise UnauthorizedError("Invalid token")
