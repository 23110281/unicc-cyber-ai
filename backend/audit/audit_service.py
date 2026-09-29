"""
Audit Logging Service (Team 4)
Handles immutable, secure audit logging with correlation ID linking.
Now database-backed.
"""
import json
from sqlalchemy.orm import Session
from backend.models import AuditLog, utc_now

def log_action(db: Session, correlation_id: str, user_id: str, role: str, action: str, 
               resource_id: str, llm_backend_used: str, outcome: str, details: dict = None):
    """
    Log an action for auditing securely into the database.
    Note: The repository pattern ensures this is append-only by not exposing any update or delete endpoints.
    
    Args:
        db: SQLAlchemy DB session.
        correlation_id: ID linking all actions in one investigation session.
        user_id: ID of the user performing the action.
        role: Role of the user.
        action: What the user is doing (e.g. 'summarize_report').
        resource_id: The report/investigation ID.
        llm_backend_used: 'ollama' or 'gemini'.
        outcome: 'success' or 'failure'.
        details: Optional dict. MUST NOT CONTAIN SECRETS.
    """
    if details:
        # Basic secrets sanitization (prevent Gemini API keys from leaking)
        safe_details = {k: v for k, v in details.items() if "key" not in k.lower() and "secret" not in k.lower()}
    else:
        safe_details = {}
        
    full_details = {
        "resource_id": resource_id,
        "llm_backend_used": llm_backend_used,
        "outcome": outcome,
        **safe_details
    }
    
    audit_entry = AuditLog(
        timestamp=utc_now(),  # stored in UTC
        action=action,
        user=user_id,
        role=role,
        correlation_id=correlation_id,
        details=json.dumps(full_details)
    )
    
    # Write to append-only log in the database
    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)
    return audit_entry

def get_audit_logs(db: Session, limit: int = 100):
    """Retrieve the most recent audit logs (For Auditor/Admin)."""
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
