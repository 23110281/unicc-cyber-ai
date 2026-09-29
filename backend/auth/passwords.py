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


# bcrypt (the password-hashing method) can only use the first 72 bytes of a password,
# and the library refuses longer ones. We never accept longer ones as new passwords,
# and a longer one typed at login simply counts as a wrong password (no crash).
MAX_PASSWORD_BYTES = 72


def verify_password(plain_password: str, hashed_password: str) -> bool:
    candidate = plain_password.encode("utf-8")
    if len(candidate) > MAX_PASSWORD_BYTES:
        return False
    return bcrypt.checkpw(candidate, hashed_password.encode("utf-8"))


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
