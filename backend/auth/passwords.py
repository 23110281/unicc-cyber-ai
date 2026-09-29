"""
Password helpers (Team 4)

Kept separate from the login-pass (JWT) code, so tools like manage_users can
hash and check passwords without needing the JWT secret.
Passwords are never stored in plain text - only a bcrypt hash is saved.
"""

import bcrypt

# Passwords that were once written in this project's public code for the demo
# accounts. Anyone can read them on GitHub, so they are refused at login even if
# an old database still contains them.
PUBLISHED_DEFAULT_PASSWORDS = {"adminpassword", "invpassword", "audpassword"}


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
