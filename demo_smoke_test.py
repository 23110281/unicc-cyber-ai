import requests
import json
import sys

BASE_URL = "http://127.0.0.1:8000/api/v1"

def print_result(step_name, passed, data=None):
    if passed:
        print(f"✅ PASS: {step_name}")
    else:
        print(f"❌ FAIL: {step_name}")
        if data:
            print(f"   Response Body: {json.dumps(data, indent=2)}")
        sys.exit(1)

def run_demo():
    print("Starting Headless Demo Smoke Test...\n")
    session = requests.Session()
    
    # 1. Login as investigator_1
    res = session.post(f"{BASE_URL}/auth/login", json={"username": "investigator_1", "password": "invpassword"})
    passed = res.status_code == 200 and "access_token" in session.cookies.get_dict()
    print_result("1. Login as investigator_1", passed, res.text if not passed else None)
    
    # 2. POST /investigation/analyze
    sample_report = "A suspected RansomwareX infection occurred on 192.168.1.100. The Lazarus Group is believed to be responsible, utilizing CVE-2023-1234. File hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."
    res = session.post(f"{BASE_URL}/investigation/analyze", json={"report_text": sample_report})
    data = res.json() if res.status_code == 200 else res.text
    passed = res.status_code == 200 and "correlation_id" in data
    print_result("2. POST /investigation/analyze", passed, data)
    correlation_id = data.get("correlation_id")
    
    # 3. POST /investigation/entities
    res = session.post(f"{BASE_URL}/investigation/entities", json={"report_text": sample_report, "correlation_id": correlation_id})
    data = res.json() if res.status_code == 200 else res.text
    has_categories = False
    if res.status_code == 200 and isinstance(data, dict):
        required_keys = ["CVE", "IP/domain", "hash", "malware", "threat actor"]
        has_categories = all(k in data and len(data[k]) > 0 for k in required_keys)
    passed = res.status_code == 200 and has_categories
    print_result("3. POST /investigation/entities", passed, data if not passed else None)
    entities = []
    for v in data.values():
        entities.extend(v)
    
    # 4. POST /investigation/threats
    res = session.post(f"{BASE_URL}/investigation/threats", json={"entities": entities, "correlation_id": correlation_id})
    data = res.json() if res.status_code == 200 else res.text
    has_threats = False
    if res.status_code == 200 and isinstance(data, dict):
        matches = data.get("matches", [])
        if len(matches) >= 2:
            valid_categories = {"exact", "strong", "partial", "weak", "unsupported"}
            has_threats = all(
                "match_category" in m and m["match_category"] in valid_categories and
                m.get("synthesized") is True and
                (0 <= m.get("confidence", -1) <= 1 or 0 <= m.get("confidence", -1) <= 100)
                for m in matches
            )
    passed = res.status_code == 200 and has_threats
    print_result("4. POST /investigation/threats", passed, data if not passed else None)
    
    # 5. POST /llm/summarize
    evidence = sample_report + "\nThreats: " + json.dumps(data)
    res = session.post(f"{BASE_URL}/llm/summarize", json={"evidence": evidence, "correlation_id": correlation_id})
    data = res.json() if res.status_code == 200 else res.text
    has_ref = False
    if res.status_code == 200 and isinstance(data, dict):
        summary = data.get("summary", "")
        # Basic substring check for one of the entities (e.g. CVE-2023-1234 or RansomwareX)
        has_ref = any(e in summary for e in ["CVE-2023-1234", "192.168.1.100", "RansomwareX", "Lazarus Group"])
    passed = res.status_code == 200 and has_ref
    print_result("5. POST /llm/summarize", passed, data if not passed else None)
    
    # 6. POST /investigation/decision
    res = session.post(f"{BASE_URL}/investigation/decision", json={
        "decision": "escalate", 
        "notes": "Verified threat matches.",
        "correlation_id": correlation_id
    })
    passed = res.status_code == 200
    print_result("6. POST /investigation/decision", passed, res.text if not passed else None)
    
    # 7. Login as auditor_1 and check audit logs
    session = requests.Session() # New session
    res = session.post(f"{BASE_URL}/auth/login", json={"username": "auditor_1", "password": "audpassword"})
    res = session.get(f"{BASE_URL}/admin/audit-logs")
    data = res.json() if res.status_code == 200 else res.text
    has_logs = False
    if res.status_code == 200 and isinstance(data, list):
        corr_logs = [log for log in data if log.get("correlation_id") == correlation_id]
        has_logs = len(corr_logs) == 5 # 5 workflow actions logged with this correlation ID
    passed = res.status_code == 200 and has_logs
    print_result("7. Login as auditor_1 & check 5 audit logs", passed, data if not passed else None)
    
    # 8. Login as investigator_1 again & hit admin config
    session = requests.Session() # New session
    session.post(f"{BASE_URL}/auth/login", json={"username": "investigator_1", "password": "invpassword"})
    res = session.get(f"{BASE_URL}/admin/config")
    passed = res.status_code == 403
    print_result("8. Admin config endpoint returns 403 for investigator", passed, res.text if not passed else None)
    
    print("\nAll automated tests passed perfectly!")

if __name__ == "__main__":
    run_demo()
