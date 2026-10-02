from http.client import HTTPConnection
import argparse
import json

METHODS = ["GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"]


def check(host, port):
    rows = []
    for method in METHODS:
        connection = HTTPConnection(host, port, timeout=5)
        headers = {
            "Origin": f"http://{host}:{port}",
            "Content-Type": "application/json"
        }
        path = "/api/method-check" if method == "POST" else "/"
        body = json.dumps({"check": True}) if method in {"POST", "PUT", "PATCH"} else None
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            response.read()
            allow = response.getheader("Allow") or "-"
            if response.status == 405:
                result = "запрещён настройкой"
            elif response.status == 501:
                result = "не реализован сервером"
            else:
                result = "обрабатывается сервером"
            rows.append((method, response.status, allow, result))
        except OSError as error:
            rows.append((method, "ERR", "-", str(error)))
        finally:
            connection.close()
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    print(f"Разведка HTTP-методов: http://{args.host}:{args.port}")
    print(f"{'METHOD':<10} {'STATUS':<8} {'ALLOW':<14} РЕЗУЛЬТАТ")
    print("-" * 72)
    for method, status, allow, result in check(args.host, args.port):
        print(f"{method:<10} {str(status):<8} {allow:<14} {result}")


if __name__ == "__main__":
    main()
