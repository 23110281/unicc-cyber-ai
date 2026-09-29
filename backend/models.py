import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean
from backend.database import Base


def utc_now() -> datetime.datetime:
    """
    The current time in UTC (world standard time), without a timezone label.

    All times in the database are stored in UTC, because this tool is used in
    several countries. The server marks them as UTC when sending them out, and
    each viewer's browser shows them in that viewer's own local time.
    """
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False)  # admin, investigator, auditor

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utc_now, nullable=False)  # always UTC
    action = Column(String, index=True, nullable=False)
    user = Column(String, index=True, nullable=False)
    role = Column(String, nullable=False)
    correlation_id = Column(String, index=True, nullable=False)
    details = Column(Text, nullable=False) # Stored as JSON string

class SystemConfig(Base):
    __tablename__ = "system_config"
    
    key = Column(String, primary_key=True, index=True)
    value = Column(String, nullable=False)
