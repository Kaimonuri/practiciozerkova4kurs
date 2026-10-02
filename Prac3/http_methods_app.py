from http.client import HTTPConnection
import json

HOST = "127.0.0.1"
PORT = int(__import__("os").environ.get("PORT", "8000"))
REQUESTS = [
    ("GET", "/"),
    ("POST", "/api/method-check"),
    ("PUT", "/api/method-check"),
    ("DELETE", "/api/method-check"),
]

for method, path in REQUESTS:
    connection = HTTPConnection(HOST, PORT, timeout=5)
    body = json.dumps({"message": "Проверка HTTP-метода"}) if method in {"POST", "PUT"} else None
    headers = {
        "Origin": f"http://{HOST}:{PORT}",
        "Content-Type": "application/json"
    }
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    response_body = response.read().decode("utf-8", errors="replace")
    print(f"{method} {path}")
    print(f"Статус: {response.status} {response.reason}")
    print(f"Allow: {response.getheader('Allow') or '-'}")
    print(f"Ответ: {response_body[:120] or '<пустой>'}")
    print()
    connection.close()

