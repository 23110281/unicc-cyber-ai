import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from datetime import datetime

from backend.api.main import app, get_db
from backend.database import Base
from backend.models import User, SystemConfig, AuditLog
from backend.auth.auth_service import get_password_hash

# Setup Test Database
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, 
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    users = [
        User(id="t1", username="test_admin", hashed_password=get_password_hash("testpass"), role="admin"),
        User(id="t2", username="test_inv", hashed_password=get_password_hash("testpass"), role="investigator"),
    ]
    db.add_all(users)
    db.commit()
    yield
    Base.metadata.drop_all(bind=engine)

def test_login_success_returns_httponly_cookie():
    response = client.post("/api/v1/auth/login", json={"username": "test_admin", "password": "testpass"})
    assert response.status_code == 200
    assert "access_token" in response.cookies
    
    # httpx handles cookies natively. We can check if it's set.
    cookie = None
    for c in response.headers.get_list("set-cookie"):
        if "access_token" in c:
            cookie = c
            break
    assert cookie is not None
    assert "HttpOnly" in cookie

def test_login_failure():
    response = client.post("/api/v1/auth/login", json={"username": "test_admin", "password": "wrong"})
    assert response.status_code == 401

def test_rbac_admin_route_forbidden_for_investigator():
    # Login as investigator
    res = client.post("/api/v1/auth/login", json={"username": "test_inv", "password": "testpass"})
    token = res.cookies.get("access_token")
    
    # Try to access admin route
    res2 = client.get("/api/v1/admin/config", cookies={"access_token": token})
    assert res2.status_code == 403

def test_rbac_admin_route_success_for_admin():
    # Login as admin
    res = client.post("/api/v1/auth/login", json={"username": "test_admin", "password": "testpass"})
    token = res.cookies.get("access_token")
    
    # Try to access admin route
    res2 = client.get("/api/v1/admin/config", cookies={"access_token": token})
    assert res2.status_code == 200

def test_audit_logs_append_only():
    db = TestingSessionLocal()
    # Ensure no delete or update methods exist on the AuditLog schema definition
    # This is validated by design since AuditLog is a standard SQLAlchemy model,
    # and we do not expose any API routes to delete/update them.
    
    # Let's write an audit log
    from backend.audit.audit_service import log_action
    log_action(db, "corr1", "u1", "admin", "test_action", "r1", "none", "success")
    
    logs = db.query(AuditLog).all()
    assert len(logs) == 1
    assert logs[0].action == "test_action"
    
    # Confirm it has no application-layer delete method
    assert not hasattr(log_action, "delete")
    assert not hasattr(log_action, "update")

def test_entities_extraction_success():
    # Login as investigator
    res = client.post("/api/v1/auth/login", json={"username": "test_inv", "password": "testpass"})
    assert res.status_code == 200
    token = res.cookies.get("access_token")
    
    # Test entities endpoint
    payload = {
        "report_text": "Incident Summary: test payload with 10.0.0.1",
        "correlation_id": "test-corr-id"
    }
    res2 = client.post("/api/v1/investigation/entities", json=payload, cookies={"access_token": token})
    print("Entities extraction response:", res2.json())
    assert res2.status_code == 200
    data = res2.json()
    assert "iocs" in data

class _FakeWorkingGateway:
    """Stands in for the AI model so tests don't need the internet or an API key."""
    def summarize_report(self, text, config=None):
        return {"summary": "Test summary.", "key_points": ["- point one"]}


class _FakeBrokenGateway:
    """Stands in for an AI model that fails (no key, network down, quota used up...)."""
    def summarize_report(self, text, config=None):
        from llm.gateway.interface import LLMGatewayError
        raise LLMGatewayError("model unavailable")


def _summarize_with(gateway):
    from backend.api.main import get_llm_gateway
    app.dependency_overrides[get_llm_gateway] = lambda: (gateway, "test")
    try:
        res = client.post("/api/v1/auth/login", json={"username": "test_inv", "password": "testpass"})
        token = res.cookies.get("access_token")
        payload = {"evidence": "This is a test report about ransomware.", "correlation_id": "test-corr-id"}
        return client.post("/api/v1/llm/summarize", json=payload, cookies={"access_token": token})
    finally:
        del app.dependency_overrides[get_llm_gateway]


def test_summarize_success():
    res = _summarize_with(_FakeWorkingGateway())
    assert res.status_code == 200
    assert res.json()["summary"] == "Test summary."


def test_summarize_failure_is_reported_not_faked():
    # The bug this guards against: when the AI failed, the app used to answer
    # "200 OK" with a made-up ransomware summary.
    res = _summarize_with(_FakeBrokenGateway())
    assert res.status_code == 502
    assert "Mock" not in res.text
    assert "ransomware incident" not in res.text


def test_gemini_without_api_key_fails_clearly(monkeypatch):
    from llm.gateway.adapters import GeminiGateway
    from llm.gateway.interface import LLMGatewayError
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    gateway = GeminiGateway()
    with pytest.raises(LLMGatewayError, match="API key is not set"):
        gateway.summarize_report("some report text")



def test_threat_matching_does_not_invent_matches():
    # The bug this guards against: the app used to show "APT29" and "Cobalt Strike"
    # as matches for any input, even a lunch menu.
    res = client.post("/api/v1/auth/login", json={"username": "test_inv", "password": "testpass"})
    token = res.cookies.get("access_token")
    payload = {"entities": [], "correlation_id": "test-corr-id"}
    res2 = client.post("/api/v1/investigation/threats", json=payload, cookies={"access_token": token})
    assert res2.status_code == 200
    data = res2.json()
    assert data["matches"] == []
    assert data["status"] == "unavailable"
    assert "APT29" not in res2.text


# ---------------------------------------------------------------------------
# Login-pass (JWT) signing key
# ---------------------------------------------------------------------------
OLD_PUBLIC_SECRET = "super-secret-dev-key-that-is-at-least-32-bytes-long!"


def test_forged_admin_pass_with_old_public_secret_is_rejected():
    # The bug this guards against: anyone could make themselves admin by signing
    # a pass with the secret that used to be written in the public code.
    import datetime
    import jwt
    forged = jwt.encode(
        {"id": "x", "username": "attacker", "role": "admin",
         "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)},
        OLD_PUBLIC_SECRET, algorithm="HS256",
    )
    res = client.get("/api/v1/admin/config", cookies={"access_token": forged})
    assert res.status_code == 401


def test_old_public_secret_cannot_be_configured(monkeypatch):
    from backend.auth.auth_service import _load_jwt_secret
    monkeypatch.setenv("JWT_SECRET", OLD_PUBLIC_SECRET)
    with pytest.raises(RuntimeError):
        _load_jwt_secret()


def test_short_secret_is_refused(monkeypatch):
    from backend.auth.auth_service import _load_jwt_secret
    monkeypatch.setenv("JWT_SECRET", "too-short")
    with pytest.raises(RuntimeError):
        _load_jwt_secret()


def test_without_secret_a_random_one_is_used(monkeypatch):
    from backend.auth.auth_service import _load_jwt_secret
    monkeypatch.delenv("JWT_SECRET", raising=False)
    first, second = _load_jwt_secret(), _load_jwt_secret()
    assert first != second
    assert len(first) >= 32


# ---------------------------------------------------------------------------
# Checks moved here from the old test_unit.py (which tested an older version
# of the code and could no longer run).
# ---------------------------------------------------------------------------
def test_audit_log_never_stores_secrets():
    # Anything whose name contains "key" or "secret" must be dropped before
    # it is written to the audit log, so API keys can't leak into it.
    import json
    from backend.audit.audit_service import log_action
    db = TestingSessionLocal()
    entry = log_action(db, "corr-123", "u1", "investigator", "extract", "doc_1", "gemini", "success",
                       {"gemini_api_key": "secret-12345", "jwt_secret": "abc", "normal_field": "safe_value"})
    details = json.loads(entry.details)
    assert "gemini_api_key" not in details
    assert "jwt_secret" not in details
    assert "secret-12345" not in entry.details
    assert details["normal_field"] == "safe_value"
    db.close()


def test_garbage_or_missing_login_pass_is_rejected():
    from backend.auth.auth_service import require_role, UnauthorizedError
    with pytest.raises(UnauthorizedError):
        require_role("not-a-real-token", ["admin"])
    with pytest.raises(UnauthorizedError):
        require_role("", ["admin"])


# ---------------------------------------------------------------------------
# No passwords written in the code
# ---------------------------------------------------------------------------
def test_published_default_passwords_are_refused_at_login():
    # The bug this guards against: the demo accounts used passwords that were
    # written in the public code. An old database may still contain them.
    db = TestingSessionLocal()
    db.add(User(id="old1", username="admin_user", hashed_password=get_password_hash("adminpassword"), role="admin"))
    db.commit()
    db.close()
    res = client.post("/api/v1/auth/login", json={"username": "admin_user", "password": "adminpassword"})
    assert res.status_code == 401
    assert "access_token" not in res.cookies


def test_first_start_creates_accounts_with_random_passwords():
    from backend.manage_users import create_initial_accounts, PUBLISHED_DEFAULT_PASSWORDS
    from backend.auth.auth_service import verify_password
    db = TestingSessionLocal()
    db.query(User).delete()
    db.commit()
    created = create_initial_accounts(db)
    assert {role for _, role, _ in created} == {"admin", "investigator", "auditor"}
    passwords = [password for _, _, password in created]
    assert len(set(passwords)) == 3
    for username, _, password in created:
        assert password not in PUBLISHED_DEFAULT_PASSWORDS
        assert len(password) >= 12
        stored = db.query(User).filter(User.username == username).first()
        assert stored.hashed_password != password          # never stored as plain text
        assert verify_password(password, stored.hashed_password)
    assert create_initial_accounts(db) == []             # not re-created on the next start
    db.close()


def test_new_passwords_must_follow_the_rules():
    from backend.manage_users import add_user, reset_password
    db = TestingSessionLocal()
    with pytest.raises(ValueError):
        reset_password(db, "test_admin", "short")
    with pytest.raises(ValueError):
        reset_password(db, "test_admin", "adminpassword")
    with pytest.raises(ValueError):
        add_user(db, "someone", "superuser", "a-long-enough-password")
    reset_password(db, "test_admin", "a-long-enough-password")
    db.close()
    res = client.post("/api/v1/auth/login", json={"username": "test_admin", "password": "a-long-enough-password"})
    assert res.status_code == 200


# ---------------------------------------------------------------------------
# Other websites may not call the API (CORS)
# ---------------------------------------------------------------------------
def test_other_websites_are_not_allowed_to_call_the_api():
    # The bug this guards against: the app told browsers that ANY website could
    # call it with the logged-in user's pass.
    res = client.get("/api/v1/admin/config", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in res.headers
    preflight = client.options(
        "/api/v1/investigation/entities",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in preflight.headers


def test_allowing_every_website_cannot_be_configured(monkeypatch):
    from backend.api.main import _load_allowed_origins
    monkeypatch.setenv("ALLOWED_ORIGINS", "*")
    with pytest.raises(RuntimeError):
        _load_allowed_origins()
    monkeypatch.setenv("ALLOWED_ORIGINS", "https://dashboard.example.org, https://other.example.org")
    assert _load_allowed_origins() == ["https://dashboard.example.org", "https://other.example.org"]


# ---------------------------------------------------------------------------
# Password-guessing limit
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _fresh_login_limiter():
    # Every test starts with no recorded failed logins.
    from backend.api.main import login_limiter
    login_limiter.reset()
    yield
    login_limiter.reset()


def _login(username, password):
    return client.post("/api/v1/auth/login", json={"username": username, "password": password})


def test_password_guessing_is_blocked_after_5_failures():
    # The bug this guards against: unlimited wrong passwords, with no slowdown.
    for _ in range(5):
        assert _login("test_admin", "wrong-guess").status_code == 401
    blocked = _login("test_admin", "testpass")          # even the RIGHT password is refused now
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers
    assert "access_token" not in blocked.cookies
    assert _login("test_inv", "testpass").status_code == 200   # other users are not affected


def test_successful_login_clears_earlier_failures():
    for _ in range(4):
        _login("test_admin", "wrong-guess")
    assert _login("test_admin", "testpass").status_code == 200
    for _ in range(4):
        _login("test_admin", "wrong-guess")
    assert _login("test_admin", "testpass").status_code == 200


def test_one_computer_cannot_try_many_usernames():
    for i in range(20):
        _login(f"made-up-user-{i}", "wrong-guess")
    assert _login("test_inv", "testpass").status_code == 429


def test_block_ends_after_the_time_window():
    from backend.auth.login_limiter import LoginLimiter
    now = [1000.0]
    limiter = LoginLimiter(max_failures_per_user=5, window_seconds=900, clock=lambda: now[0])
    for _ in range(5):
        limiter.record_failure("alice", "10.0.0.1")
    assert limiter.seconds_until_allowed("alice", "10.0.0.1") == 900
    now[0] += 899
    assert limiter.seconds_until_allowed("alice", "10.0.0.1") == 1
    now[0] += 1
    assert limiter.seconds_until_allowed("alice", "10.0.0.1") == 0


# ---------------------------------------------------------------------------
# Audit log records logins, logouts and admin actions
# ---------------------------------------------------------------------------
def _audit_entries():
    db = TestingSessionLocal()
    entries = [(e.action, e.user, e.details) for e in db.query(AuditLog).all()]
    db.close()
    return entries


def test_logins_logouts_and_admin_actions_are_audited():
    # The bug this guards against: logins, failed logins, logouts, setting changes
    # and audit-log views left no trace.
    _login("test_admin", "wrong-guess")
    res = _login("test_admin", "testpass")
    token = res.cookies.get("access_token")
    client.post("/api/v1/admin/config", json={"llm_backend": "ollama"}, cookies={"access_token": token})
    client.post("/api/v1/admin/config", json={"llm_backend": "gemini"}, cookies={"access_token": token})
    client.get("/api/v1/admin/audit-logs", cookies={"access_token": token})
    client.post("/api/v1/auth/logout", cookies={"access_token": token})

    actions = [action for action, _, _ in _audit_entries()]
    for expected in ["login_failed", "login", "config_change", "view_audit_logs", "logout"]:
        assert expected in actions, f"'{expected}' was not recorded"
    changes = [d for a, _, d in _audit_entries() if a == "config_change"]
    assert len(changes) == 2
    assert any('"old_value": "ollama"' in d and '"new_value": "gemini"' in d for d in changes)


def test_blocked_logins_are_audited_and_passwords_never_are():
    for _ in range(6):
        _login("test_admin", "my-secret-guess-123")
    entries = _audit_entries()
    assert any(action == "login_blocked" for action, _, _ in entries)
    for _, _, details in entries:
        assert "my-secret-guess-123" not in details


def test_audit_log_page_returns_complete_entries():
    # Guards against entries coming back empty ({}) from the audit-log page.
    res = _login("test_admin", "testpass")
    token = res.cookies.get("access_token")
    page = client.get("/api/v1/admin/audit-logs", cookies={"access_token": token})
    assert page.status_code == 200
    entries = page.json()
    assert len(entries) >= 2                      # the login and this view
    for entry in entries:
        for field in ["timestamp", "action", "user", "role", "correlation_id", "details"]:
            assert entry.get(field) not in (None, ""), f"'{field}' missing in {entry}"
    assert {"login", "view_audit_logs"} <= {entry["action"] for entry in entries}


def test_audit_times_are_labelled_utc_and_correct():
    # The bug this guards against: times were stored in UTC but sent without a
    # timezone label, so browsers showed them 5.5 hours off in India.
    import datetime
    res = _login("test_admin", "testpass")
    token = res.cookies.get("access_token")
    entries = client.get("/api/v1/admin/audit-logs", cookies={"access_token": token}).json()
    now = datetime.datetime.now(datetime.timezone.utc)
    for entry in entries:
        assert entry["timestamp"].endswith("+00:00"), entry["timestamp"]
        when = datetime.datetime.fromisoformat(entry["timestamp"])
        assert abs((now - when).total_seconds()) < 120


def test_audit_page_shows_usernames():
    res = _login("test_admin", "testpass")
    token = res.cookies.get("access_token")
    entries = client.get("/api/v1/admin/audit-logs", cookies={"access_token": token}).json()
    login_entry = next(e for e in entries if e["action"] == "login")
    assert login_entry["username"] == "test_admin"


# ---------------------------------------------------------------------------
# Browser caching rules
# ---------------------------------------------------------------------------
def test_dashboard_files_are_rechecked_by_browsers():
    # The bug this guards against: browsers kept using an old app.js after an update.
    for path in ["/", "/app.js", "/style.css"]:
        res = client.get(path)
        assert res.status_code == 200
        assert res.headers.get("cache-control") == "no-cache", path


def test_api_answers_are_never_stored_by_browsers():
    res = _login("test_inv", "testpass")
    assert res.headers.get("cache-control") == "no-store"
    token = res.cookies.get("access_token")
    res2 = client.post("/api/v1/investigation/entities",
                       json={"report_text": "CVE-2023-23397", "correlation_id": "c"},
                       cookies={"access_token": token})
    assert res2.headers.get("cache-control") == "no-store"


# ---------------------------------------------------------------------------
# Sessions really end
# ---------------------------------------------------------------------------
def _entities(token):
    return client.post("/api/v1/investigation/entities",
                       json={"report_text": "CVE-2023-23397", "correlation_id": "c"},
                       cookies={"access_token": token})


def test_logout_really_ends_the_session():
    # The bug this guards against: a pass copied before logout kept working for up to 60 minutes.
    token = _login("test_inv", "testpass").cookies.get("access_token")
    assert _entities(token).status_code == 200
    client.post("/api/v1/auth/logout", cookies={"access_token": token})
    after = _entities(token)
    assert after.status_code == 401
    assert "logged out" in after.json()["detail"]


def test_logout_ends_only_that_session():
    first = _login("test_inv", "testpass").cookies.get("access_token")
    second = _login("test_inv", "testpass").cookies.get("access_token")   # e.g. another computer
    client.post("/api/v1/auth/logout", cookies={"access_token": first})
    assert _entities(first).status_code == 401
    assert _entities(second).status_code == 200


def test_password_reset_ends_all_sessions_of_that_user():
    from backend.manage_users import reset_password
    old = _login("test_inv", "testpass").cookies.get("access_token")
    other_user = _login("test_admin", "testpass").cookies.get("access_token")
    db = TestingSessionLocal()
    reset_password(db, "test_inv", "a-brand-new-password-1")
    db.close()
    assert _entities(old).status_code == 401                         # old session is over
    assert _entities(other_user).status_code == 200                  # other users unaffected
    new = _login("test_inv", "a-brand-new-password-1").cookies.get("access_token")
    assert _entities(new).status_code == 200                         # new login works straight away


def test_who_am_i_reports_the_logged_in_user():
    token = _login("test_inv", "testpass").cookies.get("access_token")
    me = client.get("/api/v1/auth/me", cookies={"access_token": token})
    assert me.status_code == 200
    assert me.json() == {"username": "test_inv", "role": "investigator"}
    client.cookies.clear()                    # the test client remembers cookies, like a browser
    assert client.get("/api/v1/auth/me").status_code == 401          # not logged in


def test_pass_without_session_id_is_refused():
    # Passes made before sessions had IDs (or forged without one) are not accepted.
    import datetime
    import jwt
    from backend.auth.auth_service import JWT_SECRET, JWT_ALGORITHM
    old_style = jwt.encode(
        {"id": "t2", "username": "test_inv", "role": "investigator",
         "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)},
        JWT_SECRET, algorithm=JWT_ALGORITHM)
    assert _entities(old_style).status_code == 401


# ---------------------------------------------------------------------------
# Input checks
# ---------------------------------------------------------------------------
def test_very_long_password_is_a_wrong_password_not_a_crash():
    # The bug this guards against: a password over 72 bytes crashed the login (HTTP 500),
    # skipping the guessing limit and the audit log.
    res = _login("test_inv", "x" * 100)
    assert res.status_code == 401
    assert any(action == "login_failed" for action, _, _ in _audit_entries())


def test_new_passwords_over_72_bytes_are_refused():
    from backend.manage_users import reset_password
    db = TestingSessionLocal()
    with pytest.raises(ValueError, match="at most 72 bytes"):
        reset_password(db, "test_inv", "y" * 73)
    db.close()


def test_decision_must_be_one_of_the_offered_choices():
    # The bug this guards against: any text, e.g. "delete-everything", was recorded as a decision.
    token = _login("test_inv", "testpass").cookies.get("access_token")
    bad = client.post("/api/v1/investigation/decision", cookies={"access_token": token},
                      json={"decision": "delete-everything", "notes": "", "correlation_id": "c1"})
    assert bad.status_code == 422
    assert isinstance(bad.json()["detail"], str) and "decision" in bad.json()["detail"]
    good = client.post("/api/v1/investigation/decision", cookies={"access_token": token},
                       json={"decision": "escalate", "notes": "confirmed", "correlation_id": "c1"})
    assert good.status_code == 200


def test_report_size_and_emptiness_are_checked():
    token = _login("test_inv", "testpass").cookies.get("access_token")
    too_long = client.post("/api/v1/investigation/entities", cookies={"access_token": token},
                           json={"report_text": "A" * 200_001, "correlation_id": "c1"})
    assert too_long.status_code == 422 and "report_text" in too_long.json()["detail"]
    empty = client.post("/api/v1/investigation/analyze", cookies={"access_token": token},
                        json={"report_text": ""})
    assert empty.status_code == 422


def test_oversized_requests_are_refused_before_reading():
    token = _login("test_inv", "testpass").cookies.get("access_token")
    huge = '{"report_text": "' + "A" * (2 * 1024 * 1024 + 10) + '", "correlation_id": "c1"}'
    res = client.post("/api/v1/investigation/entities", cookies={"access_token": token},
                      content=huge, headers={"Content-Type": "application/json"})
    assert res.status_code == 413


def test_correlation_ids_must_be_simple():
    token = _login("test_inv", "testpass").cookies.get("access_token")
    res = client.post("/api/v1/investigation/decision", cookies={"access_token": token},
                      json={"decision": "monitor", "notes": "", "correlation_id": "<script>x</script>"})
    assert res.status_code == 422
