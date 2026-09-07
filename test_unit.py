import pytest
import os
import json
from datetime import datetime, timedelta
import jwt

# Mock modules for testing
from backend.auth.auth_service import LocalUserStore, create_jwt_token, JWT_SECRET, JWT_ALGORITHM, require_role, UnauthorizedError, ForbiddenError
from backend.audit.audit_service import log_action, logger
from llm.gateway.interface import LLMInterface, LLMTimeoutError, LLMGatewayError

# Fakes
class FakeSuccessLLM(LLMInterface):
    def summarize_report(self, text, config=None):
        return {"summary": "Fake summary of the threat.", "key_points": ["Point 1", "Point 2"]}
    def extract_entities(self, text, config=None):
        return {"cves": ["CVE-2024-1234"], "iocs": ["1.2.3.4"], "threat_actors": ["APT-Fake"], "malware": ["FakeRansom"]}
    def investigate_synthesis(self, query, retrieved_evidence, config=None):
        return {"assessment": "Evidence matches.", "confidence": "High", "cited_sources": ["doc_123"]}

class FakeTimeoutLLM(LLMInterface):
    def summarize_report(self, text, config=None): raise LLMTimeoutError("Timed out")
    def extract_entities(self, text, config=None): raise LLMTimeoutError("Timed out")
    def investigate_synthesis(self, q, e, config=None): raise LLMTimeoutError("Timed out")

class FakeErrorLLM(LLMInterface):
    def summarize_report(self, text, config=None): raise LLMGatewayError("Gateway error")
    def extract_entities(self, text, config=None): raise LLMGatewayError("Gateway error")
    def investigate_synthesis(self, q, e, config=None): raise LLMGatewayError("Gateway error")

class MockResponse:
    def __init__(self):
        self.cookies = {}
    def set_cookie(self, key, value, httponly=False):
        self.cookies[key] = {"value": value, "httponly": httponly}

def test_llm_fakes():
    success = FakeSuccessLLM()
    assert success.extract_entities("")["cves"] == ["CVE-2024-1234"]
    
    timeout = FakeTimeoutLLM()
    with pytest.raises(LLMTimeoutError):
        timeout.summarize_report("")
        
    err = FakeErrorLLM()
    with pytest.raises(LLMGatewayError):
        err.summarize_report("")

def test_auth_service():
    store = LocalUserStore()
    
    # Login success
    user = store.authenticate("admin_user", "adminpassword")
    assert user is not None
    assert user["role"] == "admin"
    
    # Login failure
    assert store.authenticate("admin_user", "wrong") is None
    
    # JWT creation
    token = create_jwt_token(user)
    decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    assert decoded["role"] == "admin"
    
    # httpOnly cookie check
    resp = MockResponse()
    resp.set_cookie("access_token", token, httponly=True)
    assert resp.cookies["access_token"]["httponly"] is True

    # Role verification
    assert require_role(token, "admin")["role"] == "admin"
    
    # Forbidden (403)
    with pytest.raises(ForbiddenError):
        require_role(token, "investigator")
        
    # Unauthorized (401)
    with pytest.raises(UnauthorizedError):
        require_role("invalid-token", "admin")
    with pytest.raises(UnauthorizedError):
        require_role("", "admin")

def test_audit_service(tmp_path):
    import logging
    # Temporarily redirect audit log to tmp_path
    log_file = tmp_path / "audit_test.log"
    handler = logging.FileHandler(log_file)
    logger.handlers = [handler]
    
    # Action with sensitive info
    log_action("corr-123", "u1", "investigator", "extract", "doc_1", "fake", "success", {
        "gemini_api_key": "secret-12345",
        "normal_field": "safe_value"
    })
    
    # Verify log
    with open(log_file, "r") as f:
        log_line = f.read().strip()
        
    data = json.loads(log_line)
    assert data["correlation_id"] == "corr-123"
    assert "gemini_api_key" not in data["details"]
    assert data["details"]["normal_field"] == "safe_value"
    assert data["outcome"] == "success"
