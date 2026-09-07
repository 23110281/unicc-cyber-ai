import socket
import json

payload = json.dumps({
    "model": "tinyllama",
    "prompt": "word " * 3000,
    "stream": False
})

req = (
    "POST /api/generate HTTP/1.1\r\n"
    "Host: localhost:11434\r\n"
    "Content-Type: application/json\r\n"
    f"Content-Length: {len(payload)}\r\n"
    "Connection: close\r\n\r\n"
    f"{payload}"
)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("localhost", 11434))
s.sendall(req.encode('utf-8'))

response = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    response += chunk

print("--- RAW HTTP RESPONSE ---")
print(response.decode('utf-8'))
