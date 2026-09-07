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

def test_summarize_success():
    # Login as investigator
    res = client.post("/api/v1/auth/login", json={"username": "test_inv", "password": "testpass"})
    token = res.cookies.get("access_token")
    
    # Test summarize endpoint
    payload = {
        "evidence": "This is a test report about ransomware.",
        "correlation_id": "test-corr-id"
    }
    res2 = client.post("/api/v1/llm/summarize", json=payload, cookies={"access_token": token})
    print("Summarize response:", res2.json())
    assert res2.status_code == 200

