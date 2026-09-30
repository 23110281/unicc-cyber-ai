import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from backend.config import get_str   # importing this also loads the .env file

# Where the database lives. Default: a SQLite file next to this code (backend/app.db).
# In Docker or on a server, point DATABASE_URL at a folder that survives rebuilds,
# e.g. sqlite:////data/app.db (four slashes = absolute path).
DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")
SQLALCHEMY_DATABASE_URL = get_str("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")

# check_same_thread=False lets FastAPI use SQLite from several threads.
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False} if SQLALCHEMY_DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
