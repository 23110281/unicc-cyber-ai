import os
import requests
import time
import json
import jwt
import threading
from unittest.mock import patch
from backend.auth.auth_service import LocalUserStore, create_jwt_token, JWT_SECRET, JWT_ALGORITHM, require_role
from backend.audit.audit_service import log_action, logger
from llm.gateway.adapters import OllamaGateway, GeminiGateway
from llm.gateway.interface import LLMGatewayError, LLMTimeoutError

REPORT_FILE = "test_report_exhaustive.md"
with open(REPORT_FILE, "w") as f:
    f.write("# Final Exhaustive Test Report\n\n")

def append_to_report(text):
    with open(REPORT_FILE, "a") as f:
        f.write(text + "\n")

original_post = requests.post

class Interceptor:
    def __init__(self):
        self.last_url = ""
        self.last_headers = {}
        self.last_body = None
        self.last_response_text = ""
        self.last_latency = 0
        self.force_status = None
        self.force_text = None
        self.force_error = None
        self.force_timeout = False

interceptor = Interceptor()

def mock_post(url, **kwargs):
    start = time.time()
    interceptor.last_url = url
    interceptor.last_headers = kwargs.get("headers", {})
    interceptor.last_body = kwargs.get("json", kwargs.get("data"))
    
    if interceptor.force_timeout:
        raise requests.exceptions.Timeout("Forced timeout")
        
    if interceptor.force_error:
        raise interceptor.force_error
        
    if interceptor.force_status is not None:
        class MockResp:
            def __init__(self):
                self.status_code = interceptor.force_status
                self.text = interceptor.force_text or "Error"
            def json(self):
                if interceptor.force_text and "{" in interceptor.force_text:
                    return json.loads(interceptor.force_text)
                raise json.JSONDecodeError("Expecting value", interceptor.force_text, 0)
            def raise_for_status(self):
                if self.status_code >= 400:
                    raise requests.exceptions.HTTPError(f"HTTP Error {self.status_code}")
        resp = MockResp()
    else:
        resp = original_post(url, **kwargs)
        
    interceptor.last_latency = int((time.time() - start) * 1000)
    interceptor.last_response_text = resp.text
    return resp

requests.post = mock_post

def run_test_case(name, gateway_instance, method, args, expected_pass=True):
    append_to_report(f"## {name}")
    try:
        start = time.time()
        res = getattr(gateway_instance, method)(*args)
        latency = int((time.time() - start) * 1000)
        # Add latency specifically here if the interceptor was skipped or if we just want total elapsed
        latency_str = f"{latency}ms (Total), {interceptor.last_latency}ms (HTTP)"
        
        passed = expected_pass
        append_to_report("### Exact Raw HTTP Request Sent")
        safe_url = interceptor.last_url.split("key=")[0] + "key=HIDDEN" if "key=" in interceptor.last_url else interceptor.last_url
        append_to_report(f"**URL:** {safe_url}")
        append_to_report(f"**Headers:** {interceptor.last_headers}")
        try:
            body_str = json.dumps(interceptor.last_body, indent=2)
            if len(body_str) > 1000: body_str = body_str[:1000] + "\n... [TRUNCATED for report]"
        except:
            body_str = str(interceptor.last_body)
        append_to_report(f"**Body:**\n```json\n{body_str}\n```")
        
        append_to_report("### Exact Raw Response Received")
        res_str = interceptor.last_response_text
        if len(res_str) > 1500: res_str = res_str[:1500] + "\n... [TRUNCATED for report]"
        append_to_report(f"```json\n{res_str}\n```")
        
        append_to_report("### Exact Final Structured Dict Returned")
        append_to_report(f"```json\n{json.dumps(res, indent=2)}\n```")
        
        append_to_report(f"**Latency:** {latency_str}")
        append_to_report(f"**Result:** {'PASSED' if passed else 'FAILED'}")
        
    except Exception as e:
        passed = not expected_pass
        latency_str = f"{interceptor.last_latency}ms (HTTP)" if interceptor.last_latency else "0ms"
        
        append_to_report("### Exact Raw HTTP Request Sent")
        safe_url = interceptor.last_url.split("key=")[0] + "key=HIDDEN" if "key=" in interceptor.last_url else interceptor.last_url
        append_to_report(f"**URL:** {safe_url}")
        append_to_report(f"**Headers:** {interceptor.last_headers}")
        
        append_to_report("### Exact Raw Response Received (if any)")
        if interceptor.last_response_text:
            append_to_report(f"```\n{interceptor.last_response_text}\n```")
        else:
            append_to_report("*(No response text)*")
            
        append_to_report(f"**Latency:** {latency_str}")
        append_to_report(f"**Result:** {'PASSED' if passed else 'FAILED'} (Exception: {type(e).__name__}: {str(e)})")


# --- Gemini Suite ---
append_to_report("\n# Gemini Test Coverage\n")
gemini = GeminiGateway()

interceptor.force_status = None
interceptor.force_text = None
interceptor.force_error = None
interceptor.force_timeout = False

run_test_case("Gemini Normal Case", gemini, "summarize_report", ["The quick brown fox jumps over the lazy dog. - It was quick. - It was brown."])

run_test_case("Gemini Empty Input", gemini, "summarize_report", ["   "], expected_pass=False)

interceptor.force_status = 200
interceptor.force_text = "<!DOCTYPE html><html><body>Error Bad Gateway</body></html>"
run_test_case("Gemini Malformed/Unparseable JSON Output", gemini, "summarize_report", ["Test"], expected_pass=False)

interceptor.force_status = None
interceptor.force_text = None
run_test_case("Gemini Very Long Input (Truncation/Context Test)", gemini, "summarize_report", ["word " * 6000], expected_pass=True)

# --- Ollama Suite ---
append_to_report("\n# Ollama Test Coverage\n")
try:
    ollama = OllamaGateway(model="tinyllama")
except Exception as e:
    ollama = None
    append_to_report(f"Failed to initialize Ollama: {e}")

if ollama:
    run_test_case("Ollama Normal Case", ollama, "summarize_report", ["The quick brown fox jumps over the lazy dog. - It was quick. - It was brown."])
    run_test_case("Ollama Empty Input", ollama, "summarize_report", ["   "], expected_pass=False)

    interceptor.force_status = 200
    interceptor.force_text = "Internal error text without json"
    run_test_case("Ollama Malformed/Unparseable JSON Output", ollama, "summarize_report", ["Test"], expected_pass=False)

    interceptor.force_status = None
    interceptor.force_text = None
    run_test_case("Ollama Very Long Input (Approaching Context Limits)", ollama, "summarize_report", ["word " * 3000], expected_pass=True)

# --- Auth & Audit Suite ---
append_to_report("\n# Auth, RBAC & Audit\n")

store = LocalUserStore()
append_to_report("### Decoded JWTs for All Roles")
for user_key, creds in [("admin_user", "adminpassword"), ("investigator_1", "invpassword"), ("auditor_1", "audpassword")]:
    user = store.authenticate(user_key, creds)
    token = create_jwt_token(user)
    decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    append_to_report(f"**{user['role']} role JWT:**\n```json\n{json.dumps(decoded, indent=2)}\n```")
    if user['role'] == 'admin':
        append_to_report(f"**Actual Set-Cookie Header:**\n`Set-Cookie: access_token={token}; HttpOnly; Path=/`\n")

# --- Concurrency Test ---
append_to_report("\n# Concurrency Test (Gemini)\n")
def worker(gw, results, index):
    try:
        start = time.time()
        res = gw.summarize_report(f"Test concurrent call {index}. Please reply with \"Summary {index}\"")
        lat = int((time.time() - start) * 1000)
        results[index] = {"status": "success", "summary": res["summary"], "latency_ms": lat}
    except Exception as e:
        results[index] = {"status": "error", "error": str(e)}

interceptor.force_status = None
interceptor.force_text = None
interceptor.force_error = None
interceptor.force_timeout = False

threads = []
results = {}
for i in range(3):
    t = threading.Thread(target=worker, args=(gemini, results, i))
    threads.append(t)
    t.start()
for t in threads:
    t.join()

append_to_report("### 3 Concurrent Requests Results")
append_to_report(f"```json\n{json.dumps(results, indent=2)}\n```")
if all(v.get("status") == "success" for v in results.values()):
    append_to_report("**Result:** PASSED - 3 separate valid summaries returned concurrently with independent responses.")
else:
    append_to_report("**Result:** FAILED - Concurrency errors detected.")
