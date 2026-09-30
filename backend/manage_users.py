"""
User account management (Team 4)

Run these from the project folder, with the virtual environment active:

    python -m backend.manage_users list
    python -m backend.manage_users add <username> <role>
    python -m backend.manage_users reset-password <username>

Roles: investigator, auditor, admin.
Passwords are typed in hidden (nothing shows on screen while you type) and are
never stored in plain text - only a bcrypt hash is saved.
"""

import getpass
import secrets
import sys
import uuid
from typing import List, Tuple

from sqlalchemy.orm import Session

from backend.auth.passwords import MAX_PASSWORD_BYTES, PUBLISHED_DEFAULT_PASSWORDS, get_password_hash
from backend.auth.sessions import end_all_sessions
from backend.models import User

ROLES = ("investigator", "auditor", "admin")
MIN_PASSWORD_LENGTH = 12

# The demo accounts created the first time the app starts with an empty database.
INITIAL_ACCOUNTS = [
    ("admin_user", "admin"),
    ("investigator_1", "investigator"),
    ("auditor_1", "auditor"),
]


def check_password_rules(password: str) -> None:
    """Raise ValueError if the password is not acceptable."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_BYTES} bytes long (about {MAX_PASSWORD_BYTES} plain letters).")
    if password in PUBLISHED_DEFAULT_PASSWORDS:
        raise ValueError("That password was published in the project's code. Choose a different one.")


def create_initial_accounts(db: Session) -> List[Tuple[str, str, str]]:
    """
    If there are no users at all, create the demo accounts with RANDOM passwords.
    Returns (username, role, password) for each account created, so the caller can
    show the passwords once. Returns an empty list if users already exist.
    """
    if db.query(User).first():
        return []

    created = []
    for username, role in INITIAL_ACCOUNTS:
        password = secrets.token_urlsafe(12)  # 16 random characters
        db.add(User(id=str(uuid.uuid4()), username=username,
                    hashed_password=get_password_hash(password), role=role))
        created.append((username, role, password))
    db.commit()
    return created


def add_user(db: Session, username: str, role: str, password: str) -> None:
    if role not in ROLES:
        raise ValueError(f"Role must be one of: {', '.join(ROLES)}")
    if db.query(User).filter(User.username == username).first():
        raise ValueError(f"User '{username}' already exists.")
    check_password_rules(password)
    db.add(User(id=str(uuid.uuid4()), username=username,
                hashed_password=get_password_hash(password), role=role))
    db.commit()


def reset_password(db: Session, username: str, password: str) -> None:
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise ValueError(f"No user named '{username}'.")
    check_password_rules(password)
    user.hashed_password = get_password_hash(password)
    db.commit()
    # Anyone still logged in as this user (maybe with the old password) is logged out.
    end_all_sessions(db, user.id)


def _ask_new_password() -> str:
    first = getpass.getpass(f"New password (at least {MIN_PASSWORD_LENGTH} characters, hidden while typing): ")
    second = getpass.getpass("Type it again: ")
    if first != second:
        raise ValueError("The two passwords did not match.")
    return first


def main(argv: List[str]) -> int:
    from backend.database import Base, SessionLocal, engine

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if len(argv) == 1 and argv[0] == "list":
            for user in db.query(User).order_by(User.username).all():
                print(f"{user.username:<20} {user.role}")
            return 0
        if len(argv) == 3 and argv[0] == "add":
            add_user(db, argv[1], argv[2], _ask_new_password())
            print(f"Created user '{argv[1]}' with role '{argv[2]}'.")
            return 0
        if len(argv) == 2 and argv[0] == "reset-password":
            reset_password(db, argv[1], _ask_new_password())
            print(f"Password changed for '{argv[1]}'.")
            return 0
        print(__doc__)
        return 1
    except ValueError as error:
        print(f"Error: {error}")
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled. Nothing was changed.")
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
