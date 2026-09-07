import requests
import json

payload = {
    "model": "tinyllama",
    "prompt": "word " * 3000,
    "stream": False
}

try:
    resp = requests.post("http://localhost:11434/api/generate", json=payload, timeout=120)
    print("Status:", resp.status_code)
    print("Headers:", resp.headers)
    print("Text:", resp.text)
except Exception as e:
    print("Exception:", e)
