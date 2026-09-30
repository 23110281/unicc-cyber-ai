"""
Settings (Team 4)

Every setting that can differ between computers - secret keys, AI model names,
addresses, security switches - is read from ENVIRONMENT VARIABLES, never written
in the code.

The easy way to set them is a file called `.env` in the project folder (copy
`.env.example` to `.env` and fill it in). This module loads that file when the app
starts. `.env` is listed in .gitignore, so secrets in it are never uploaded.
Variables that are already set in the environment win over the file.

The full list of settings, with explanations, is in `.env.example` and the README.
"""

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"


def load_env_file(path: Path = ENV_FILE) -> bool:
    """Load settings from a .env file if there is one. Returns True if a file was loaded."""
    if os.environ.get("LOAD_DOTENV", "1") == "0" or not path.is_file():
        return False
    from dotenv import load_dotenv
    load_dotenv(path, override=False)   # real environment variables take priority
    return True


def get_str(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip() or default


def get_int(name: str, default: int) -> int:
    value = os.environ.get(name, "").strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        raise RuntimeError(f"Setting {name} must be a whole number, got {value!r}.")


def get_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name, "").strip().lower()
    if not value:
        return default
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise RuntimeError(f"Setting {name} must be true or false, got {value!r}.")


# Load .env as soon as any part of the backend is imported (backend.database imports
# this module first), so every other module sees the settings.
load_env_file()
