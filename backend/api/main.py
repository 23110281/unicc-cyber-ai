import json
import logging
import math
import os
import uuid
from contextlib import asynccontextmanager
from datetime import timezone
from fastapi import FastAPI, Depends, HTTPException, status, Response, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import List, Optional

from backend.database import engine, Base, get_db
from backend.models import User, SystemConfig
from backend.auth.auth_service import (
    DBUserStore, create_jwt_token, require_role,
    UnauthorizedError, ForbiddenError, PUBLISHED_DEFAULT_PASSWORDS
)
from backend.auth.login_limiter import LoginLimiter
from backend.manage_users import create_initial_accounts
from backend.audit.audit_service import log_action, get_audit_logs
from llm.gateway.adapters import GeminiGateway, OllamaGateway
from llm.gateway.interface import LLMGatewayError, LLMTimeoutError

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create database tables
    Base.metadata.create_all(bind=engine)
    
    # First start with an empty database: create the demo accounts with RANDOM
    # passwords and show them once in this window. No password is written in the code.
    db = next(get_db())
    created = create_initial_accounts(db)
    if created:
        log = logging.getLogger("uvicorn.error")
        log.warning("No user accounts existed, so these were created. The passwords are shown ONLY ONCE - write them down now:")
        for username, role, password in created:
            log.warning(f"    username: {username:<16} password: {password}   ({role})")
        log.warning("To change a password later: python -m backend.manage_users reset-password <username>")

    if not db.query(SystemConfig).filter(SystemConfig.key == "llm_backend").first():
        db.add(SystemConfig(key="llm_backend", value="gemini"))
        
    db.commit()
    db.close()
    yield

app = FastAPI(title="UNICC Cyber AI Gateway", lifespan=lifespan)

# Which OTHER websites may call this API from a user's browser (CORS).
# The dashboard is served by this same app, so it needs no permission, and by
# default NO other website is allowed. If the dashboard is ever hosted at a
# different address, list that address in ALLOWED_ORIGINS, e.g.
#     ALLOWED_ORIGINS=https://dashboard.example.org
def _load_allowed_origins() -> List[str]:
    origins = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()]
    if "*" in origins:
        raise RuntimeError("ALLOWED_ORIGINS must list specific addresses, not '*' (that would allow every website).")
    return origins

_allowed_origins = _load_allowed_origins()
if _allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

# Exception handlers for Custom Auth errors
@app.exception_handler(UnauthorizedError)
async def unauthorized_handler(request: Request, exc: UnauthorizedError):
    return JSONResponse(status_code=401, content={"detail": str(exc)})

@app.exception_handler(ForbiddenError)
async def forbidden_handler(request: Request, exc: ForbiddenError):
    return JSONResponse(status_code=403, content={"detail": str(exc)})

# Counts failed logins to stop password guessing (see backend/auth/login_limiter.py).
login_limiter = LoginLimiter()

ALL_ROLES = ["investigator", "auditor", "admin"]


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# --- Dependencies ---
def get_current_user_token(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise UnauthorizedError("Not authenticated")
    return token

def get_investigator_user(token: str = Depends(get_current_user_token)):
    return require_role(token, ["investigator", "admin"])

def get_admin_user(token: str = Depends(get_current_user_token)):
    return require_role(token, ["admin"])

def get_auditor_user(token: str = Depends(get_current_user_token)):
    return require_role(token, ["auditor", "admin"])

def get_llm_gateway(db: Session = Depends(get_db)):
    config = db.query(SystemConfig).filter(SystemConfig.key == "llm_backend").first()
    backend = config.value if config else "gemini"
    
    if backend == "ollama":
        try:
            return OllamaGateway(), "ollama"
        except Exception as e:
            raise HTTPException(status_code=503, detail=f"Ollama unavailable: {e}")
    else:
        try:
            return GeminiGateway(), "gemini"
        except Exception as e:
            raise HTTPException(status_code=503, detail=f"Gemini unavailable: {e}")

# --- Pydantic Schemas ---
class LoginRequest(BaseModel):
    username: str
    password: str
    
class AnalyzeRequest(BaseModel):
    report_text: str

class EntitiesRequest(BaseModel):
    report_text: str
    correlation_id: str

class ThreatsRequest(BaseModel):
    entities: List[str]
    correlation_id: str

class SummarizeRequest(BaseModel):
    evidence: str
    correlation_id: str

class DecisionRequest(BaseModel):
    decision: str
    notes: str
    correlation_id: str

class ConfigUpdate(BaseModel):
    llm_backend: str

# --- Endpoints ---
@app.post("/api/v1/auth/login")
def login(req: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = _client_ip(request)
    # Recorded in the audit log for failed attempts. Never the password.
    attempt = {"attempted_username": req.username[:64], "ip": ip}

    # 1) Too many recent failures for this username or this computer? Refuse without checking.
    wait_seconds = login_limiter.seconds_until_allowed(req.username, ip)
    if wait_seconds:
        log_action(db, "auth", "anonymous", "none", "login_blocked", "auth", "none", "failure",
                   {**attempt, "retry_after_seconds": wait_seconds})
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed login attempts. Try again in {math.ceil(wait_seconds / 60)} minute(s).",
            headers={"Retry-After": str(wait_seconds)},
        )

    # 2) Passwords that were public in the project's code are never accepted.
    if req.password in PUBLISHED_DEFAULT_PASSWORDS:
        login_limiter.record_failure(req.username, ip)
        log_action(db, "auth", "anonymous", "none", "login_failed", "auth", "none", "failure",
                   {**attempt, "reason": "published default password"})
        raise HTTPException(
            status_code=401,
            detail="This password was published in the project's code and is no longer accepted. "
                   "An admin can set a new one with: python -m backend.manage_users reset-password <username>",
        )

    # 3) Normal check.
    user = DBUserStore(db).authenticate(req.username, req.password)
    if not user:
        login_limiter.record_failure(req.username, ip)
        log_action(db, "auth", "anonymous", "none", "login_failed", "auth", "none", "failure",
                   {**attempt, "reason": "invalid credentials"})
        raise HTTPException(status_code=401, detail="Invalid credentials")

    login_limiter.record_success(req.username)
    log_action(db, "auth", user["id"], user["role"], "login", "auth", "none", "success", {"ip": ip})

    token = create_jwt_token(user)
    response.set_cookie(
        key="access_token", 
        value=token, 
        httponly=True, 
        max_age=3600, 
        samesite="lax",
        secure=False # Set to True in production with HTTPS
    )
    return {"message": "Logged in successfully", "role": user["role"]}

@app.post("/api/v1/auth/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if token:
        try:
            user = require_role(token, ALL_ROLES)
            log_action(db, "auth", user["id"], user["role"], "logout", "auth", "none", "success",
                       {"ip": _client_ip(request)})
        except (UnauthorizedError, ForbiddenError):
            pass  # an expired or invalid pass: nothing to record, just clear the cookie
    response.delete_cookie("access_token")
    return {"message": "Logged out successfully"}

@app.get("/api/v1/admin/audit-logs")
def api_get_audit_logs(user: dict = Depends(get_auditor_user), db: Session = Depends(get_db)):
    # Looking at the audit log is itself recorded. This is done FIRST: saving a new
    # entry clears rows already loaded in this session, which would send them empty.
    log_action(db, "admin", user["id"], user["role"], "view_audit_logs", "audit_log", "none", "success")
    usernames = {u.id: u.username for u in db.query(User).all()}
    return [
        {
            "id": entry.id,
            # Stored in UTC; the "+00:00" label lets each browser convert it to local time.
            "timestamp": entry.timestamp.replace(tzinfo=timezone.utc).isoformat(),
            "action": entry.action,
            "user": entry.user,
            "username": usernames.get(entry.user, entry.user),
            "role": entry.role,
            "correlation_id": entry.correlation_id,
            "details": entry.details,
        }
        for entry in get_audit_logs(db)
    ]

@app.get("/api/v1/admin/config")
def api_get_config(user: dict = Depends(get_admin_user), db: Session = Depends(get_db)):
    config = db.query(SystemConfig).filter(SystemConfig.key == "llm_backend").first()
    return {"llm_backend": config.value if config else "gemini"}

@app.post("/api/v1/admin/config")
def api_update_config(req: ConfigUpdate, user: dict = Depends(get_admin_user), db: Session = Depends(get_db)):
    if req.llm_backend not in ["gemini", "ollama"]:
        log_action(db, "admin", user["id"], user["role"], "config_change", "system_config", "none", "failure",
                   {"setting": "llm_backend", "rejected_value": req.llm_backend[:64]})
        raise HTTPException(status_code=400, detail="Invalid backend")

    config = db.query(SystemConfig).filter(SystemConfig.key == "llm_backend").first()
    old_value = config.value if config else None
    if config:
        config.value = req.llm_backend
    else:
        db.add(SystemConfig(key="llm_backend", value=req.llm_backend))
    db.commit()
    log_action(db, "admin", user["id"], user["role"], "config_change", "system_config", "none", "success",
               {"setting": "llm_backend", "old_value": old_value, "new_value": req.llm_backend})
    return {"message": "Config updated"}


@app.post("/api/v1/investigation/analyze")
def analyze_report(req: AnalyzeRequest, user: dict = Depends(get_investigator_user), db: Session = Depends(get_db)):
    # Simply generates a correlation_id and returns the text
    correlation_id = str(uuid.uuid4())
    log_action(db, correlation_id, user["id"], user["role"], "upload_report", "doc_new", "none", "success")
    return {"correlation_id": correlation_id, "text": req.report_text}

@app.post("/api/v1/investigation/entities")
def extract_entities(req: EntitiesRequest, user: dict = Depends(get_investigator_user), 
                     db: Session = Depends(get_db), gw_dep = Depends(get_llm_gateway)):
    gw, backend_name = gw_dep
    try:
        res = gw.extract_entities(req.report_text)
        log_action(db, req.correlation_id, user["id"], user["role"], "extract_entities", "doc_current", backend_name, "success")
        return res
    except LLMGatewayError as e:
        log_action(db, req.correlation_id, user["id"], user["role"], "extract_entities", "doc_current", backend_name, "failure", {"error": str(e)})
        raise HTTPException(status_code=502, detail=str(e))

THREAT_MATCHING_UNAVAILABLE = (
    "Threat matching is not connected yet. It needs the historical-threat search "
    "(retrieval) service from Team 2. No matches are shown rather than invented ones."
)

@app.post("/api/v1/investigation/threats")
def get_threat_matches(req: ThreatsRequest, user: dict = Depends(get_investigator_user), db: Session = Depends(get_db)):
    # Matching new indicators against historical threats needs Team 2's retrieval
    # service, which is not wired in yet. Until it is, we say so plainly and return
    # no matches. We never return made-up matches: an investigator could act on them.
    log_action(db, req.correlation_id, user["id"], user["role"], "threat_match", "doc_current", "none",
               "unavailable", {"reason": "retrieval service not connected"})
    return {"matches": [], "status": "unavailable", "message": THREAT_MATCHING_UNAVAILABLE}

@app.post("/api/v1/llm/summarize")
def summarize_investigation(req: SummarizeRequest, user: dict = Depends(get_investigator_user), 
                            db: Session = Depends(get_db), gw_dep = Depends(get_llm_gateway)):
    gw, backend_name = gw_dep
    try:
        res = gw.summarize_report(req.evidence)
        log_action(db, req.correlation_id, user["id"], user["role"], "summarize_investigation", "doc_current", backend_name, "success")
        return res
    except LLMGatewayError as e:
        log_action(db, req.correlation_id, user["id"], user["role"], "summarize_investigation", "doc_current", backend_name, "failure", {"error": str(e)})
        raise HTTPException(status_code=502, detail=str(e))

@app.post("/api/v1/investigation/decision")
def final_decision(req: DecisionRequest, user: dict = Depends(get_investigator_user), db: Session = Depends(get_db)):
    # Final step in the workflow where investigator makes a decision
    log_action(db, req.correlation_id, user["id"], user["role"], "final_decision", "doc_current", "none", "success", {"decision": req.decision, "notes": req.notes})
    return {"message": "Decision recorded"}

# Serve frontend static files
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
