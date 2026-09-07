from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os

# Create a local SQLite database file in the backend directory
DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

# connect_args is needed for SQLite to allow multi-threading in FastAPI
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
