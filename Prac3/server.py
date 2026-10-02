from datetime import date, datetime, timedelta, timezone
from hashlib import pbkdf2_hmac, sha256
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
import base64
import json
import mimetypes
import os
import re
import secrets

import psycopg
from psycopg.errors import UniqueViolation

ROOT = Path(__file__).resolve().parent
ENV_FILE = ROOT / ".env"
if ENV_FILE.exists():
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            if key in {"DATABASE_URL", "ADMIN_LOGIN", "ADMIN_PASSWORD", "HTTPS"}:
                os.environ.setdefault(key, value)
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
DATABASE_URL = os.environ.get("DATABASE_URL")
HTTPS = os.environ.get("HTTPS", "0") == "1"
COOKIE_NAME = "__Host-session" if HTTPS else "session"
SERVICES = {"Поддерживающая уборка", "Генеральная уборка", "Уборка после ремонта"}
STATUSES = {"Новая", "В работе", "Выполнена", "Отменена"}
NAME_RE = re.compile(r"^[А-ЯЁ][а-яё]*(?:-[А-ЯЁ][а-яё]*)?$")
PATRONYMIC_RE = re.compile(r"^[А-ЯЁ][а-яё]*(?:(?:-| )[А-ЯЁа-яё]+)*$")
LOGIN_RE = re.compile(r"^[A-Za-z]{1,20}$")
PHONE_RE = re.compile(r"^8\(\d{3}\)\d{3}-\d{2}-\d{2}$")


def db():
    return psycopg.connect(DATABASE_URL)


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(32)
    digest = pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return base64.b64encode(salt).decode() + ":" + base64.b64encode(digest).decode()


def password_valid(password, saved):
    try:
        salt_text, digest_text = saved.split(":", 1)
        salt = base64.b64decode(salt_text)
        expected = base64.b64decode(digest_text)
        actual = pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
        return secrets.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def init_db():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS users (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                surname VARCHAR(20) NOT NULL, firstname VARCHAR(20) NOT NULL,
                patronymic VARCHAR(20) NOT NULL, login VARCHAR(20) NOT NULL UNIQUE,
                password_hash TEXT NOT NULL, address VARCHAR(100) NOT NULL,
                is_admin BOOLEAN NOT NULL DEFAULT FALSE,
                consent_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )""")
            cur.execute("""CREATE TABLE IF NOT EXISTS sessions (
                token_hash CHAR(64) PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TIMESTAMPTZ NOT NULL
            )""")
            cur.execute("""CREATE TABLE IF NOT EXISTS orders (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                service TEXT NOT NULL, address VARCHAR(100) NOT NULL,
                visit_date DATE NOT NULL, phone VARCHAR(16) NOT NULL,
                status TEXT NOT NULL DEFAULT 'Новая',
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )""")
            cur.execute("DELETE FROM sessions WHERE expires_at <= now()")
            admin_login = os.environ.get("ADMIN_LOGIN")
            admin_password = os.environ.get("ADMIN_PASSWORD")
            if admin_login and admin_password:
                cur.execute("SELECT id FROM users WHERE login = %s", (admin_login,))
                if cur.fetchone() is None:
                    cur.execute("""INSERT INTO users
                        (surname, firstname, patronymic, login, password_hash, address, is_admin)
                        VALUES (%s,%s,%s,%s,%s,%s,TRUE)""",
                        ("Администратор", "Сайта", "Служебный", admin_login,
                         password_hash(admin_password), "Служебная запись"))


class Handler(BaseHTTPRequestHandler):
    def method_not_allowed(self):
        data = json.dumps(
            {"error": "Метод запрещён", "allowed": ["GET", "POST"]},
            ensure_ascii=False
        ).encode("utf-8")
        self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
        self.headers_common()
        self.send_header("Allow", "GET, POST")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    do_HEAD = method_not_allowed
    do_PUT = method_not_allowed
    do_PATCH = method_not_allowed
    do_DELETE = method_not_allowed
    do_OPTIONS = method_not_allowed
    do_TRACE = method_not_allowed
    do_CONNECT = method_not_allowed

    def headers_common(self):
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        if HTTPS:
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    def respond(self, status, payload, cookie=None):
        data = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.headers_common()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 10_000:
            raise ValueError("Некорректный размер запроса")
        return json.loads(self.rfile.read(length))

    def user(self):
        jar = SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
            token = jar[COOKIE_NAME].value
        except (KeyError, ValueError):
            return None
        token_hash = sha256(token.encode()).hexdigest()
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("""SELECT u.id, u.login, u.firstname, u.is_admin
                    FROM sessions s JOIN users u ON u.id=s.user_id
                    WHERE s.token_hash=%s AND s.expires_at>now()""", (token_hash,))
                return cur.fetchone()

    def cookie_value(self, token, max_age=None):
        parts = [f"{COOKIE_NAME}={token}", "Path=/", "HttpOnly", "SameSite=Lax"]
        if HTTPS:
            parts.append("Secure")
        if max_age is not None:
            parts.append(f"Max-Age={max_age}")
        return "; ".join(parts)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/me":
            user = self.user()
            self.respond(200, {"user": {"login": user[1], "firstname": user[2], "is_admin": user[3]} if user else None})
            return
        if path == "/api/orders":
            user = self.user()
            if not user:
                self.respond(401, {"error": "Сначала войдите в аккаунт"})
                return
            with db() as conn:
                with conn.cursor() as cur:
                    if user[3]:
                        cur.execute("""SELECT o.id,o.service,o.address,o.visit_date,o.phone,o.status,u.login
                            FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 100""")
                    else:
                        cur.execute("""SELECT id,service,address,visit_date,phone,status
                            FROM orders WHERE user_id=%s ORDER BY id DESC LIMIT 100""", (user[0],))
                    rows = cur.fetchall()
            keys = ("id", "service", "address", "date", "phone", "status", "login") if user[3] else ("id", "service", "address", "date", "phone", "status")
            self.respond(200, {"orders": [dict(zip(keys, row)) for row in rows]})
            return
        if path == "/":
            path = "/index.html"
        if path not in {"/index.html", "/style.css", "/app.js"}:
            self.respond(404, {"error": "Страница не найдена"})
            return
        data = (ROOT / path[1:]).read_bytes()
        self.send_response(200)
        self.headers_common()
        self.send_header("Content-Type", mimetypes.guess_type(path)[0] + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        path = urlsplit(self.path).path
        origin = self.headers.get("Origin", "")
        expected = ("https" if HTTPS else "http") + "://" + self.headers.get("Host", "")
        if origin != expected:
            self.respond(403, {"error": "Недопустимый источник запроса"})
            return
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            self.respond(415, {"error": "Нужен JSON"})
            return
        try:
            data = self.read_json()
            if not isinstance(data, dict):
                raise ValueError("Некорректные данные")
            if path == "/api/register":
                self.register(data)
            elif path == "/api/login":
                self.login(data)
            elif path == "/api/logout":
                self.logout()
            elif path == "/api/orders":
                self.create_order(data)
            elif path == "/api/orders/status":
                self.set_status(data)
            else:
                self.respond(404, {"error": "Маршрут не найден"})
        except (ValueError, KeyError, TypeError) as error:
            self.respond(400, {"error": str(error)})
        except psycopg.Error:
            self.respond(500, {"error": "Ошибка базы данных"})

    def register(self, data):
        surname = str(data["surname"]).strip()
        firstname = str(data["firstname"]).strip()
        patronymic = str(data["patronymic"]).strip()
        login = str(data["login"]).strip()
        password = str(data["password"])
        address = str(data["address"]).strip()
        if not (NAME_RE.fullmatch(surname) and NAME_RE.fullmatch(firstname) and PATRONYMIC_RE.fullmatch(patronymic)):
            raise ValueError("Проверьте ФИО")
        if any(len(x) > 20 for x in (surname, firstname, patronymic)) or not LOGIN_RE.fullmatch(login):
            raise ValueError("Проверьте длину полей и логин")
        if not (8 <= len(password) <= 128 and re.fullmatch(r"[A-Za-z0-9$#@!]+", password)
                and re.search("[A-Z]", password) and re.search("[a-z]", password)
                and re.search("[0-9]", password) and re.search("[$#@!]", password)):
            raise ValueError("Пароль должен содержать латинские буквы обоих регистров, цифру и символ $#@!")
        if not address or len(address) > 100 or data.get("consent") is not True:
            raise ValueError("Укажите адрес и согласие на обработку данных")
        try:
            with db() as conn:
                with conn.cursor() as cur:
                    cur.execute("""INSERT INTO users
                        (surname,firstname,patronymic,login,password_hash,address)
                        VALUES (%s,%s,%s,%s,%s,%s) RETURNING id""",
                        (surname, firstname, patronymic, login, password_hash(password), address))
                    user_id = cur.fetchone()[0]
        except UniqueViolation:
            self.respond(409, {"error": "Логин уже занят"})
            return
        self.start_session(user_id, login, firstname, False)

    def login(self, data):
        login = str(data["login"])
        password = str(data["password"])
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id,login,firstname,is_admin,password_hash FROM users WHERE login=%s", (login,))
                row = cur.fetchone()
        if not row or not password_valid(password, row[4]):
            self.respond(401, {"error": "Неверный логин или пароль"})
            return
        self.start_session(*row[:4])

    def start_session(self, user_id, login, firstname, is_admin):
        token = secrets.token_urlsafe(32)
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES (%s,%s,%s)",
                            (sha256(token.encode()).hexdigest(), user_id, datetime.now(timezone.utc) + timedelta(days=7)))
        self.respond(200, {"user": {"login": login, "firstname": firstname, "is_admin": is_admin}},
                     self.cookie_value(token, 604800))

    def logout(self):
        jar = SimpleCookie()
        jar.load(self.headers.get("Cookie", ""))
        if COOKIE_NAME in jar:
            with db() as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM sessions WHERE token_hash=%s", (sha256(jar[COOKIE_NAME].value.encode()).hexdigest(),))
        self.respond(200, {"ok": True}, self.cookie_value("", 0))

    def create_order(self, data):
        user = self.user()
        if not user:
            self.respond(401, {"error": "Сначала войдите в аккаунт"})
            return
        service = str(data["service"])
        address = str(data["address"]).strip()
        phone = str(data["phone"])
        visit_date = date.fromisoformat(str(data["date"]))
        if service not in SERVICES or not address or len(address) > 100 or not PHONE_RE.fullmatch(phone) or visit_date < date.today():
            raise ValueError("Проверьте услугу, адрес, телефон и дату")
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("""INSERT INTO orders(user_id,service,address,visit_date,phone)
                    VALUES (%s,%s,%s,%s,%s) RETURNING id""", (user[0], service, address, visit_date, phone))
                order_id = cur.fetchone()[0]
        self.respond(201, {"id": order_id, "status": "Новая"})

    def set_status(self, data):
        user = self.user()
        if not user or not user[3]:
            self.respond(403, {"error": "Доступ только для администратора"})
            return
        status = str(data["status"])
        order_id = int(data["id"])
        if status not in STATUSES or order_id < 1:
            raise ValueError("Некорректный статус или номер заявки")
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE orders SET status=%s WHERE id=%s RETURNING id", (status, order_id))
                if cur.fetchone() is None:
                    self.respond(404, {"error": "Заявка не найдена"})
                    return
        self.respond(200, {"ok": True})


if __name__ == "__main__":
    if not DATABASE_URL:
        raise SystemExit("Set DATABASE_URL for PostgreSQL connection")
    init_db()
    print(f"Open http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
