import requests

def run():
    session = requests.Session()
    res = session.post("http://127.0.0.1:8000/api/v1/auth/login", json={"username": "investigator_1", "password": "invpassword"})
    print("Login status:", res.status_code)
    print("Cookies after login:", session.cookies.get_dict())
    
    res = session.post("http://127.0.0.1:8000/api/v1/investigation/analyze", json={"report_text": "test report"})
    print("Analyze status:", res.status_code)
    print("Analyze text:", res.text)

if __name__ == "__main__":
    run()
