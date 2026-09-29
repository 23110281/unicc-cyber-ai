import hashlib
import logging
import math
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import timezone
from fastapi import FastAPI, Depends, HTTPException, Response, Request, UploadFile, File
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import List, Literal

from backend.config import get_bool, get_int, get_str   # loads the .env file first
from backend.database import engine, Base, get_db
from backend.models import User, SystemConfig
from backend.auth.auth_service import (
    DBUserStore, create_jwt_token, require_role, TOKEN_EXPIRE_MINUTES,
    UnauthorizedError, ForbiddenError
)
from backend.auth.passwords import PUBLISHED_DEFAULT_PASSWORDS
from backend.auth.login_limiter import LoginLimiter
from backend.auth.sessions import SessionEndedError, check_session, revoke_token
from backend.manage_users import create_initial_accounts
from backend.audit.audit_service import log_action, get_audit_logs
from backend.ingest.file_extractor import (
    ALLOWED_EXTENSIONS, FileExtractionError, ReportTooLongError, extract_text, file_extension
)
from llm.gateway.adapters import GeminiGateway, OllamaGateway
from llm.gateway.interface import LLMGatewayError, LLMTimeoutError
from llm.gateway.ioc_extractor import extract_iocs

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
        # First start: which AI backend to use until an admin changes it in System Config.
        first_backend = get_str("DEFAULT_LLM_BACKEND", "gemini")
        if first_backend not in ("gemini", "ollama"):
            raise RuntimeError("DEFAULT_LLM_BACKEND must be 'gemini' or 'ollama'.")
        db.add(SystemConfig(key="llm_backend", value=first_backend))
        
    db.commit()
    for warning in _settings_warnings(db):
        logging.getLogger("uvicorn.error").warning(warning)
    db.close()
    yield


def _settings_warnings(db: Session) -> List[str]:
    """Settings that are fine for testing on this computer but not for real use."""
    warnings = []
    if not get_bool("COOKIE_SECURE", False):
        warnings.append("COOKIE_SECURE is off: fine at http://127.0.0.1, but turn it on when the app is served over HTTPS.")
    backend = db.query(SystemConfig).filter(SystemConfig.key == "llm_backend").first()
    if backend and backend.value == "gemini" and not os.environ.get("GEMINI_API_KEY"):
        warnings.append("GEMINI_API_KEY is not set: AI summaries will fail until it is set in .env (or switch to Ollama).")
    return warnings

app = FastAPI(title="UNICC Cyber AI Gateway", lifespan=lifespan)

def _size_limit(path: str):
    """The largest request allowed on this address, and the message shown when it is exceeded."""
    if path == UPLOAD_PATH:
        return MAX_UPLOAD_BYTES + MULTIPART_OVERHEAD_BYTES, (
            f"File too large (limit {MAX_UPLOAD_BYTES // (1024 * 1024)} MB). Split the report, or paste its text instead.")
    return MAX_BODY_BYTES, (
        f"Request too large (limit {MAX_BODY_BYTES // (1024 * 1024)} MB). Shorten the report or split it.")


class LimitRequestSize:
    """
    Refuse oversized requests, so one huge upload can't fill the server's memory or disk.

    Two checks, because a request can arrive in two ways:
    - it announces its size up front (Content-Length): refused at once, before any of it is read;
    - it arrives in pieces without announcing a size ("chunked"): the bytes are counted as they
      arrive, and the request is stopped as soon as it goes over the limit. Checking only the
      announced size would let such a request through at any size.
    """
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit, message = _size_limit(scope.get("path", ""))

        length = dict(scope.get("headers") or []).get(b"content-length", b"")
        if length.isdigit() and int(length) > limit:
            return await JSONResponse(status_code=413, content={"detail": message})(scope, receive, send)

        received = 0

        async def counting_receive():
            nonlocal received
            event = await receive()
            if event["type"] == "http.request":
                received += len(event.get("body", b""))
                if received > limit:
                    raise HTTPException(status_code=413, detail=message)
            return event

        await self.app(scope, counting_receive, send)


app.add_middleware(LimitRequestSize)


@app.middleware("http")
async def set_cache_rules(request: Request, call_next):
    """
    Tell browsers how to cache what we send.

    - API answers (/api/...) contain investigation data and audit logs:
      "no-store" means the browser must never keep a copy on disk.
    - Dashboard files (index.html, app.js, style.css): "no-cache" means the
      browser may keep a copy but must ask the server before each use. The
      server answers "not changed" (304) when it is still current, so this is
      cheap - and after an update every user gets the new version at once.
    """
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    else:
        response.headers.setdefault("Cache-Control", "no-cache")
    return response


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

@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception):
    """Last safety net: never show a crash's internals to the user."""
    ref = _new_error_reference()
    _server_log.error(f"[error ref {ref}] Unexpected error on {request.method} {request.url.path}",
                      exc_info=(type(exc), exc, exc.__traceback__))
    return JSONResponse(status_code=500, content={
        "detail": f"Something went wrong on the server. Reference: {ref} - an administrator can find the details in the server log."})

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """Turn "the input broke a rule" errors into one readable sentence for the dashboard."""
    messages = []
    for error in exc.errors()[:3]:
        field = ".".join(str(part) for part in error.get("loc", []) if part != "body")
        messages.append(f"{field}: {error.get('msg', 'invalid value')}" if field else error.get("msg", "invalid value"))
    return JSONResponse(status_code=422, content={"detail": "Invalid input - " + "; ".join(messages)})

@app.exception_handler(ForbiddenError)
async def forbidden_handler(request: Request, exc: ForbiddenError):
    return JSONResponse(status_code=403, content={"detail": str(exc)})

# Counts failed logins to stop password guessing (see backend/auth/login_limiter.py).
login_limiter = LoginLimiter(
    max_failures_per_user=get_int("LOGIN_MAX_FAILURES_PER_USER", 5),
    max_failures_per_ip=get_int("LOGIN_MAX_FAILURES_PER_IP", 20),     # 0 = off (see login_limiter.py)
    window_seconds=get_int("LOGIN_BLOCK_MINUTES", 15) * 60,
)

ALL_ROLES = ["investigator", "auditor", "admin"]


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# --- Dependencies ---
def get_current_user_token(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise UnauthorizedError("Not authenticated")
    return token

def get_session_user(token: str = Depends(get_current_user_token), db: Session = Depends(get_db)) -> dict:
    """A valid pass (signature and expiry) whose session has not been ended."""
    user = require_role(token, ALL_ROLES)
    try:
        check_session(db, user)
    except SessionEndedError as ended:
        raise UnauthorizedError(str(ended))
    return user

def _require(user: dict, roles: List[str]) -> dict:
    if user.get("role") not in roles:
        raise ForbiddenError(f"Your role ({user.get('role')}) is not allowed to do this.")
    return user

def get_investigator_user(user: dict = Depends(get_session_user)):
    return _require(user, ["investigator", "admin"])

def get_admin_user(user: dict = Depends(get_session_user)):
    return _require(user, ["admin"])

def get_auditor_user(user: dict = Depends(get_session_user)):
    return _require(user, ["auditor", "admin"])

class _UnavailableGateway:
    """Stands in for an AI backend that could not be set up, so that failure is
    handled exactly like any other AI failure (safe message, audit entry)."""
    def __init__(self, reason: str):
        self.reason = reason

    def _fail(self, *args, **kwargs):
        raise LLMGatewayError(self.reason)

    summarize_report = extract_entities = investigate_synthesis = _fail


def get_llm_gateway(db: Session = Depends(get_db)):
    config = db.query(SystemConfig).filter(SystemConfig.key == "llm_backend").first()
    backend = config.value if config else "gemini"
    try:
        return (OllamaGateway() if backend == "ollama" else GeminiGateway()), backend
    except Exception as e:
        return _UnavailableGateway(f"The '{backend}' backend could not be set up: {e}"), backend


_server_log = logging.getLogger("uvicorn.error")


def _new_error_reference() -> str:
    return secrets.token_hex(4).upper()


def _ai_failure(db: Session, user: dict, correlation_id: str, action: str, backend_name: str, error: Exception) -> HTTPException:
    """
    Record an AI failure in full for admins, and return a SAFE message for the user.

    Raw errors can reveal internal addresses, library names or the AI provider's own
    replies - useful to an attacker, useless to an investigator. The full text goes to
    the server log and the audit log under a short reference code; the user sees the
    code, which an administrator can look up. Admins also see the details directly.
    """
    ref = _new_error_reference()
    _server_log.error(f"[error ref {ref}] {action} failed with the '{backend_name}' AI backend: {error}")
    log_action(db, correlation_id, user["id"], user["role"], action, "doc_current", backend_name, "failure",
               {"error": str(error)[:2000], "error_ref": ref})

    timed_out = isinstance(error, LLMTimeoutError)
    message = ("The AI model took too long to answer. Please try again." if timed_out
               else "The AI model could not produce an answer right now.")
    if user.get("role") == "admin":
        message += f" Details (shown to admins only): {str(error)[:500]}"
    message += f" Reference: {ref} - an administrator can find the details in the server and audit logs."
    return HTTPException(status_code=504 if timed_out else 502, detail=message)

# --- Input limits ---
# Every request is checked against these before the app does any work with it.
MAX_REPORT_CHARS = 200_000          # roughly a 50-60 page report
MAX_EVIDENCE_CHARS = MAX_REPORT_CHARS + 20_000
MAX_NOTES_CHARS = 5_000
MAX_ENTITIES = 500
MAX_ENTITY_CHARS = 512
MAX_BODY_BYTES = 2 * 1024 * 1024    # 2 MB for any single request...
MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # ...except a report file: PDFs with pictures are often several MB
MULTIPART_OVERHEAD_BYTES = 64 * 1024 # the few extra bytes a browser adds around an uploaded file
UPLOAD_PATH = "/api/v1/investigation/upload"
CORRELATION_ID = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9-]+$")

# --- Pydantic Schemas ---
class LoginRequest(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)

class AnalyzeRequest(BaseModel):
    report_text: str = Field(min_length=1, max_length=MAX_REPORT_CHARS)

class EntitiesRequest(BaseModel):
    report_text: str = Field(min_length=1, max_length=MAX_REPORT_CHARS)
    correlation_id: str = CORRELATION_ID

class ThreatsRequest(BaseModel):
    entities: List[str] = Field(max_length=MAX_ENTITIES)
    correlation_id: str = CORRELATION_ID

class SummarizeRequest(BaseModel):
    evidence: str = Field(min_length=1, max_length=MAX_EVIDENCE_CHARS)
    correlation_id: str = CORRELATION_ID

class DecisionRequest(BaseModel):
    decision: Literal["escalate", "monitor", "dismiss"]    # only the choices the dashboard offers
    notes: str = Field(default="", max_length=MAX_NOTES_CHARS)
    correlation_id: str = CORRELATION_ID

class ConfigUpdate(BaseModel):
    llm_backend: str = Field(max_length=32)

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
        max_age=TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=get_bool("COOKIE_SECURE", False),   # True when served over HTTPS (see .env.example)
    )
    return {"message": "Logged in successfully", "role": user["role"]}

@app.post("/api/v1/auth/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if token:
        try:
            user = require_role(token, ALL_ROLES)
            check_session(db, user)
            revoke_token(db, user)   # this pass is refused from now on, even if someone copied it
            log_action(db, "auth", user["id"], user["role"], "logout", "auth", "none", "success",
                       {"ip": _client_ip(request)})
        except (UnauthorizedError, ForbiddenError, SessionEndedError):
            pass  # an expired, invalid or already-ended pass: nothing to record, just clear the cookie
    response.delete_cookie("access_token")
    return {"message": "Logged out successfully"}

@app.get("/api/v1/auth/me")
def who_am_i(user: dict = Depends(get_session_user)):
    """Lets the dashboard ask "am I still logged in, and as whom?" (e.g. after a page refresh)."""
    return {"username": user.get("username"), "role": user.get("role")}

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
    # The fingerprint (hash) of the text links this investigation to an uploaded file's
    # audit entry, without storing the report itself in the audit log.
    log_action(db, correlation_id, user["id"], user["role"], "upload_report", "doc_new", "none", "success",
               {"characters": len(req.report_text), "text_sha256": _sha256(req.report_text.encode("utf-8"))})
    return {"correlation_id": correlation_id, "text": req.report_text}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_filename(name: str) -> str:
    """The file's name as the user's computer sent it: printable characters only, shortened."""
    return "".join(ch for ch in (name or "") if ch.isprintable())[:128] or "(no name)"


@app.post(UPLOAD_PATH)
def upload_report_file(file: UploadFile = File(...), user: dict = Depends(get_investigator_user),
                       db: Session = Depends(get_db)):
    """
    Read a report from an uploaded .txt, .pdf or .docx file and return its text.

    It only returns the text: the dashboard puts it in the paste box, the investigator
    can check or edit it, and the analysis starts the same way as for pasted text.
    The file itself is not kept. Its name and fingerprints (hashes) go in the audit log.

    (A plain "def", not "async def": reading a PDF takes real work, and FastAPI runs a
    plain function in a separate thread, so other users are not kept waiting meanwhile.)
    """
    filename = _safe_filename(file.filename)
    content = file.file.read(MAX_UPLOAD_BYTES + 1)
    details = {"filename": filename, "file_bytes": len(content), "file_sha256": _sha256(content)}

    def refuse(status: int, reason: str):
        log_action(db, "upload", user["id"], user["role"], "upload_report_file", "doc_new", "none", "failure",
                   {**details, "reason": reason[:256]})
        raise HTTPException(status_code=status, detail=reason)

    if len(content) > MAX_UPLOAD_BYTES:
        refuse(413, f"File too large (limit {MAX_UPLOAD_BYTES // (1024 * 1024)} MB). "
                    "Split the report, or paste its text instead.")
    if file_extension(filename) not in ALLOWED_EXTENSIONS:
        refuse(415, f"Files of type '{file_extension(filename) or 'unknown'}' can't be uploaded. "
                    f"Accepted formats: {', '.join(sorted(ALLOWED_EXTENSIONS))}.")
    try:
        text = extract_text(filename, content, MAX_REPORT_CHARS)
    except ReportTooLongError as e:
        refuse(413, str(e))
    except FileExtractionError as e:
        refuse(400, str(e))
    except Exception as e:
        # A problem inside a file-reading library: the file is refused like any other
        # unreadable file; the technical details go to the server log only.
        ref = _new_error_reference()
        _server_log.error(f"[error ref {ref}] Reading uploaded file failed: {type(e).__name__}: {e}")
        refuse(400, f"This file could not be read. Reference: {ref}")

    log_action(db, "upload", user["id"], user["role"], "upload_report_file", "doc_new", "none", "success",
               {**details, "characters": len(text), "text_sha256": _sha256(text.encode("utf-8"))})
    return {"text": text, "filename": filename, "characters": len(text)}

@app.post("/api/v1/investigation/entities")
def extract_entities(req: EntitiesRequest, user: dict = Depends(get_investigator_user),
                     db: Session = Depends(get_db)):
    # Pattern-based stand-in extractor (no AI) until Team 1's pipeline is connected.
    # It needs no AI model, so this step works whichever backend is selected - or if
    # none is reachable.
    res = extract_iocs(req.report_text)
    log_action(db, req.correlation_id, user["id"], user["role"], "extract_entities", "doc_current", "none", "success")
    return res

THREAT_MATCHING_UNAVAILABLE = (
    "Threat matching is not connected yet. It needs the historical-threat search "
    "(retrieval) service from Team 2. No matches are shown rather than invented ones."
)

@app.post("/api/v1/investigation/threats")
def get_threat_matches(req: ThreatsRequest, user: dict = Depends(get_investigator_user), db: Session = Depends(get_db)):
    if any(len(entity) > MAX_ENTITY_CHARS for entity in req.entities):
        raise HTTPException(status_code=422, detail=f"Invalid input - each entity must be at most {MAX_ENTITY_CHARS} characters.")
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
        raise _ai_failure(db, user, req.correlation_id, "summarize_investigation", backend_name, e)

@app.post("/api/v1/investigation/decision")
def final_decision(req: DecisionRequest, user: dict = Depends(get_investigator_user), db: Session = Depends(get_db)):
    # Final step in the workflow where investigator makes a decision
    log_action(db, req.correlation_id, user["id"], user["role"], "final_decision", "doc_current", "none", "success", {"decision": req.decision, "notes": req.notes})
    return {"message": "Decision recorded"}

# Serve frontend static files
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
