"""Сервер ЧистоДома: регистрация, вход, заявки и защита пользовательских данных."""

from datetime import date, datetime, timedelta, timezone
from hashlib import pbkdf2_hmac, sha256
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import urlsplit
import base64
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import ssl

import psycopg
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from psycopg.errors import UniqueViolation

ROOT = Path(__file__).resolve().parent
# Пароли и ключ берём из настроек, в коде их не записываем.
ENV_FILE = ROOT / ".env"
if ENV_FILE.exists():
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            if key in {"DATABASE_URL", "ADMIN_LOGIN", "ADMIN_PASSWORD", "HTTPS", "DATA_ENCRYPTION_KEY"}:
                os.environ.setdefault(key, value)
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
REDIRECT_PORT = int(os.environ.get("REDIRECT_PORT", "0"))
DATABASE_URL = os.environ.get("DATABASE_URL")
DB_HOST = os.environ.get("DB_HOST")
HTTPS = os.environ.get("HTTPS", "0") == "1"
# При HTTPS используем cookie с префиксом __Host-: без Domain, с Secure и Path=/.
COOKIE_NAME = "__Host-session" if HTTPS else "session"
SERVICES = {"Поддерживающая уборка", "Генеральная уборка", "Уборка после ремонта"}
STATUSES = {"Новая", "В работе", "Выполнена", "Отменена"}
# Проверяем поля на сервере, потому что проверки в браузере можно отключить.
NAME_RE = re.compile(r"^[А-ЯЁ][а-яё]*(?:-[А-ЯЁ][а-яё]*)?$")
PATRONYMIC_RE = re.compile(r"^[А-ЯЁ][а-яё]*(?:(?:-| )[А-ЯЁа-яё]+)*$")
LOGIN_RE = re.compile(r"^[A-Za-z]{1,20}$")
PHONE_RE = re.compile(r"^8\(\d{3}\)\d{3}-\d{2}-\d{2}$")
DATA_KEY = os.environ.get("DATA_ENCRYPTION_KEY")
FERNET = Fernet(DATA_KEY.encode()) if DATA_KEY else None


# ШИФРОВАНИЕ ПЕРСОНАЛЬНЫХ ДАННЫХ
# Здесь я шифрую ФИО, адреса и телефоны перед записью в PostgreSQL.
# Используется Fernet: он шифрует строку и позволяет заметить изменение шифротекста.
# В таблице вместо обычного адреса будет строка, начинающаяся с enc:.
# Ключ берётся из DATA_ENCRYPTION_KEY, а не записывается прямо в код.
# Если украсть только базу, без ключа эти поля прочитать не получится.
# Но если получить и базу, и ключ, данные можно расшифровать.
# Поэтому ключ нужно сохранять отдельно и не публиковать. При его потере данные не восстановить.
# Логин, даты, услуги и статусы здесь не шифруются.
def encrypt(value):
    if not FERNET:
        raise RuntimeError("Set DATA_ENCRYPTION_KEY for personal data encryption")
    return "enc:" + FERNET.encrypt(value.encode()).decode()


# РАСШИФРОВКА ДАННЫХ
# Чтобы показать адрес и телефон пользователю, сервер расшифровывает нужные поля.
# Разрешение на просмотр проверяется в обработчике заявки до отправки ответа.
# Само шифрование не заменяет проверку прав: это разные уровни защиты.
# Проверка enc: нужна для совместимости со старыми записями без шифрования.
def decrypt(value):
    return FERNET.decrypt(value[4:].encode()).decode() if value.startswith("enc:") else value


# ПОДКЛЮЧЕНИЕ К БАЗЕ
# Адрес базы, имя пользователя и пароль берём из переменных окружения.
# В Docker сайт работает с ролью cleaning_app, у которой нет SUPERUSER.
# Роль cleaning используется для администрирования базы, сайт под ней не работает.
# При этом cleaning_app владеет таблицами и может создавать их в public.
# Это нужно текущему init_db(), но для рабочего сайта права можно сделать ещё уже.
# Пароль лежит в локальном env-файле, который исключён из Git и Docker-контекста.
def db():
    if DB_HOST:
        return psycopg.connect(
            host=DB_HOST,
            port=int(os.environ.get("DB_PORT", "5432")),
            dbname=os.environ.get("DB_NAME", "cleaning"),
            user=os.environ.get("DB_USER", "cleaning"),
            password=os.environ.get("DB_PASSWORD"),
        )
    return psycopg.connect(DATABASE_URL)


# ХРАНЕНИЕ ПАРОЛЕЙ
# Здесь я не сохраняю пароль в исходном виде и не шифрую его обратимым способом.
# Использую PBKDF2-HMAC-SHA256: из пароля получается хеш для последующей проверки.
# Для каждого пароля создаётся своя случайная соль размером 32 байта.
# Поэтому одинаковые пароли у двух пользователей будут иметь разные сохранённые значения.
# Соль не является секретом: она сохраняется рядом с хешем через двоеточие.
# 260 000 итераций делают каждый подбор пароля дороже по времени.
# Но хеширование не заменяет ограничение попыток входа — такого ограничения пока нет.
def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(32)
    digest = pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return base64.b64encode(salt).decode() + ":" + base64.b64encode(digest).decode()


# ПРОВЕРКА ПАРОЛЯ ПРИ ВХОДЕ
# Из сохранённой строки достаём соль и хеш.
# Считаем хеш введённого пароля с той же солью и тем же числом итераций.
# Сравниваем результат через compare_digest, без раннего выхода при первом отличии.
# Исходный пароль из базы не извлекается: его там вообще нет.
# Если запись имеет неправильный формат, возвращаем False.
def password_valid(password, saved):
    try:
        salt_text, digest_text = saved.split(":", 1)
        salt = base64.b64decode(salt_text)
        expected = base64.b64decode(digest_text)
        actual = pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
        # Сравниваем хеши через compare_digest, чтобы не выдавать совпавшую часть по времени ответа.
        return secrets.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


# СОЗДАНИЕ ТАБЛИЦ
# При запуске создаются users, sessions и orders, если их ещё нет.
# UNIQUE у login не позволяет зарегистрировать два одинаковых логина.
# Внешние ключи связывают заявки и сессии с существующим пользователем.
# ON DELETE CASCADE удаляет связанные записи при удалении пользователя.
# Старые открытые ФИО, адреса и телефоны шифруются при запуске.
# Администратор создаётся из настроек окружения, только если такого логина ещё нет.
# Имя пользователя сайта и роль PostgreSQL — не одно и то же.
def init_db():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS users (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                surname TEXT NOT NULL, firstname TEXT NOT NULL,
                patronymic TEXT NOT NULL, login VARCHAR(20) NOT NULL UNIQUE,
                password_hash TEXT NOT NULL, address TEXT NOT NULL,
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
                service TEXT NOT NULL, address TEXT NOT NULL,
                visit_date DATE NOT NULL, phone TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Новая',
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )""")
            # Названия таблиц и полей заданы здесь, пользователь их не передаёт.
            # Если остались старые открытые данные, шифруем их при запуске.
            for table, columns in {
                "users": ("surname", "firstname", "patronymic", "address"),
                "orders": ("address", "phone"),
            }.items():
                for column in columns:
                    cur.execute(f"ALTER TABLE {table} ALTER COLUMN {column} TYPE TEXT")
                    cur.execute(f"SELECT id, {column} FROM {table} WHERE {column} NOT LIKE 'enc:%'")
                    for row_id, value in cur.fetchall():
                        cur.execute(f"UPDATE {table} SET {column}=%s WHERE id=%s", (encrypt(value), row_id))
            cur.execute("DELETE FROM sessions WHERE expires_at <= now()")
            admin_login = os.environ.get("ADMIN_LOGIN")
            admin_password = os.environ.get("ADMIN_PASSWORD")
            if admin_login and admin_password:
                cur.execute("SELECT id FROM users WHERE login = %s", (admin_login,))
                if cur.fetchone() is None:
                    cur.execute("""INSERT INTO users
                        (surname, firstname, patronymic, login, password_hash, address, is_admin)
                        VALUES (%s,%s,%s,%s,%s,%s,TRUE)""",
                        (encrypt("Администратор"), encrypt("Сайта"), encrypt("Служебный"), admin_login,
                         password_hash(admin_password), encrypt("Служебная запись")))


# Это учебный сервер. Для размещения в интернете его ещё нужно доработать.
class Handler(BaseHTTPRequestHandler):
    # ОГРАНИЧЕНИЕ HTTP-МЕТОДОВ
    # Для сайта нужны GET для чтения и POST для отправки форм и изменения данных.
    # PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE и CONNECT ниже привязаны к этому обработчику.
    # Он возвращает 405 Method Not Allowed и Allow: GET, POST.
    # Это явный запрет ненужных методов, а не просто отсутствие обработчика.
    # Сам по себе запрет методов не заменяет проверку входа, роли и данных.
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

    # ЗАЩИТНЫЕ HTTP-ЗАГОЛОВКИ
    # Это инструкции браузеру, которые я добавляю к ответам приложения.
    # CSP разрешает скрипты и стили своего сайта, запрещает встроенные скрипты и объекты.
    # frame-ancestors none и X-Frame-Options DENY запрещают показывать сайт во фрейме.
    # Это уменьшает риск clickjacking, когда чужая страница перекрывает кнопки сайта.
    # X-Content-Type-Options nosniff запрещает угадывать тип файла вместо указанного сервером.
    # Referrer-Policy ограничивает передачу адреса исходной страницы при переходах.
    # Permissions-Policy запрещает камеру, микрофон и геолокацию, они сайту не нужны.
    # COOP same-origin ограничивает взаимодействие с окнами других источников.
    # Cache-Control no-store запрещает сохранять ответы в кеше.
    # HSTS отправляется только при HTTPS и просит браузер дальше использовать HTTPS.
    # Заголовки дополняют защиту, но не исправляют ошибки в SQL или проверке прав.
    # У встроенных ошибок BaseHTTPRequestHandler этот набор может отсутствовать.
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

    # ОТПРАВКА ОТВЕТА
    # Формируем JSON с правильной кодировкой, длиной и защитными заголовками.
    # При входе добавляем Set-Cookie — так браузер получает сессионный токен.
    # При выходе тем же заголовком удаляем cookie через Max-Age=0.
    # Пароль пользователя в ответ не возвращаем.
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

    # ОГРАНИЧЕНИЕ ВХОДЯЩИХ ДАННЫХ
    # Принимаем тело запроса размером от 1 до 10 000 байт.
    # Это не даёт отправить в форму очень большой JSON и загрузить его целиком в память.
    # После чтения разбираем JSON; его структуру дальше проверяет do_POST().
    # От большого количества маленьких запросов эта проверка не защищает.
    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 10_000:
            raise ValueError("Некорректный размер запроса")
        return json.loads(self.rfile.read(length))

    # ПРОВЕРКА СЕССИИ
    # Из cookie берём случайный токен и считаем его SHA-256-хеш.
    # В базе ищем совпадение хеша и проверяем expires_at: срок должен быть больше текущего времени.
    # Если cookie нет или сессия закончилась, пользователь считается не вошедшим.
    # По действующей сессии получаем ID и роль, не доверяя данным о роли из браузера.
    # Эта проверка вызывается при доступе к защищённым данным и действиям.
    # Страница, CSS, регистрация и вход доступны без действующей сессии.
    def user(self):
        jar = SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
            token = jar[COOKIE_NAME].value
        except (KeyError, ValueError):
            return None
        # Ищем сессию по хешу токена и проверяем, что её срок ещё не истёк.
        token_hash = sha256(token.encode()).hexdigest()
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("""SELECT u.id, u.login, u.firstname, u.is_admin
                    FROM sessions s JOIN users u ON u.id=s.user_id
                    WHERE s.token_hash=%s AND s.expires_at>now()""", (token_hash,))
                return cur.fetchone()

    # ЗАЩИТА СЕССИОННОЙ COOKIE
    # Cookie — небольшое значение, которое браузер отправляет серверу при следующих запросах.
    # Здесь она содержит случайный токен сессии, а не пароль, ФИО или адрес пользователя.
    # HttpOnly запрещает JavaScript читать эту cookie через document.cookie.
    # Secure при HTTPS запрещает передавать её по обычному HTTP.
    # SameSite=Lax ограничивает отправку cookie в запросах с других сайтов и уменьшает риск CSRF.
    # Path=/ делает cookie доступной для маршрутов нашего сайта.
    # Max-Age задаёт время жизни: при входе 604800 секунд, то есть 7 дней.
    # В HTTPS имя __Host-session требует Secure, Path=/ и отсутствия Domain.
    # HttpOnly не устраняет XSS целиком: вредный скрипт всё ещё мог бы выполнять действия в браузере.
    # Плашка «Мы используем cookie» — отдельное уведомление, она не создаёт авторизацию.
    def cookie_value(self, token, max_age=None):
        parts = [f"{COOKIE_NAME}={token}", "Path=/", "HttpOnly", "SameSite=Lax"]
        if HTTPS:
            parts.append("Secure")
        if max_age is not None:
            parts.append(f"Max-Age={max_age}")
        return "; ".join(parts)

    # ПОЛУЧЕНИЕ СТРАНИЦ И ЗАЯВОК
    # /api/me возвращает текущего пользователя, а /api/orders — доступные ему заявки.
    # Для заявок сначала проверяется действующая сессия.
    # Администратор видит все заявки, обычный пользователь — только WHERE user_id=%s.
    # ID владельца берётся из сессии, а не из параметра, который можно подменить в браузере.
    # Так пользователь не может получить чужие заявки простой заменой ID — это защита от IDOR.
    # Для файлов есть список разрешённых путей: index.html, style.css и app.js.
    # Поэтому .env и другие файлы проекта через этот обработчик скачать нельзя.
    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/me":
            user = self.user()
            self.respond(200, {"user": {"login": user[1], "firstname": decrypt(user[2]), "is_admin": user[3]} if user else None})
            return
        if path == "/api/orders":
            user = self.user()
            if not user:
                self.respond(401, {"error": "Сначала войдите в аккаунт"})
                return
            with db() as conn:
                with conn.cursor() as cur:
                    # Все заявки доступны только администратору.
                    if user[3]:
                        cur.execute("""SELECT o.id,o.service,o.address,o.visit_date,o.phone,o.status,u.login
                            FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 100""")
                    else:
                        # Обычному пользователю отдаём только его заявки. ID берём из сессии, а не из запроса.
                        cur.execute("""SELECT id,service,address,visit_date,phone,status
                            FROM orders WHERE user_id=%s ORDER BY id DESC LIMIT 100""", (user[0],))
                    rows = cur.fetchall()
            keys = ("id", "service", "address", "date", "phone", "status", "login") if user[3] else ("id", "service", "address", "date", "phone", "status")
            orders = []
            for row in rows:
                order = dict(zip(keys, row))
                order["address"] = decrypt(order["address"])
                order["phone"] = decrypt(order["phone"])
                orders.append(order)
            self.respond(200, {"orders": orders})
            return
        if path == "/":
            path = "/index.html"
        # Отдаём только эти три файла, чтобы нельзя было скачать .env или другие файлы сервера.
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

    # ПРОВЕРКА ЗАПРОСОВ ФОРМ И ЗАЩИТА ОТ CSRF
    # Сначала сравниваем Origin запроса с адресом приложения.
    # Если запрос пришёл с чужого сайта или Origin отсутствует, отвечаем 403.
    # Также требуем Content-Type application/json, обычная HTML-форма с другого сайта не подходит.
    # Это вместе с SameSite у cookie уменьшает риск отправки действий от имени пользователя.
    # Отдельного CSRF-токена в формах нет, здесь используется проверка Origin и JSON.
    # Ожидаемый адрес строится из Host; для публичного сайта нужен список допустимых хостов.
    # После этого проверяем размер JSON, тип объекта и вызываем нужный обработчик.
    # Ошибки данных возвращаем как 400, ошибки БД — общим сообщением без SQL и секретов.
    def do_POST(self):
        path = urlsplit(self.path).path
        # Для защиты от CSRF проверяем, что POST пришёл с нашего сайта и содержит JSON.
        # Дополнительно помогает SameSite у cookie. Отдельного CSRF-токена здесь нет.
        # Адрес берём из Host; для публичного сайта стоит добавить список разрешённых хостов.
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
        # Не показываем пользователю текст SQL-ошибки и внутренние данные базы.
        except psycopg.Error:
            self.respond(500, {"error": "Ошибка базы данных"})

    # РЕГИСТРАЦИЯ И ПРОВЕРКА ДАННЫХ
    # Проверки браузера можно обойти, поэтому здесь заново проверяются все поля регистрации.
    # Для ФИО и логина используются допустимые форматы и ограничения длины.
    # Пароль должен иметь 8–128 символов, буквы обоих регистров, цифру и символ из $#@!.
    # Для адреса проверяется наличие и длина, согласие должно быть именно True.
    # Без согласия регистрация не выполняется, даже если обойти required в браузере.
    # Пароль хешируем, а ФИО и адрес шифруем перед записью.
    # Значения передаются в SQL отдельно через %s: пользовательский ввод не становится SQL-командой.
    # UNIQUE и обработка UniqueViolation защищают от повторного логина, в том числе при одновременных запросах.
    # После успешной регистрации создаём сессию.
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
        # Значения передаём отдельно через %s, чтобы ввод пользователя не стал частью SQL-команды.
        # Так же сделано в остальных запросах с пользовательскими данными.
        try:
            with db() as conn:
                with conn.cursor() as cur:
                    cur.execute("""INSERT INTO users
                        (surname,firstname,patronymic,login,password_hash,address)
                        VALUES (%s,%s,%s,%s,%s,%s) RETURNING id""",
                        (encrypt(surname), encrypt(firstname), encrypt(patronymic), login,
                         password_hash(password), encrypt(address)))
                    user_id = cur.fetchone()[0]
        except UniqueViolation:
            self.respond(409, {"error": "Логин уже занят"})
            return
        self.start_session(user_id, login, firstname, False)

    # ВХОД В АККАУНТ
    # Ищем пользователя по логину параметрическим SQL-запросом и проверяем хеш пароля.
    # При неизвестном логине и неверном пароле текст один: «Логин или пароль некорректен».
    # Так сообщение не уточняет, существует ли учётная запись.
    # Разница во времени ответа всё ещё возможна, а ограничения числа попыток пока нет.
    # При успешном входе выдаём новый случайный токен, пароль обратно не отправляем.
    # Логин и пароль передаются по HTTPS в теле JSON, а не в адресной строке.
    def login(self, data):
        login = str(data["login"])
        password = str(data["password"])
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id,login,firstname,is_admin,password_hash FROM users WHERE login=%s", (login,))
                row = cur.fetchone()
        # При ошибке входа не уточняем, что именно неверно: логин или пароль.
        # Время ответа всё ещё может отличаться, а защита от перебора пока не добавлена.
        if not row or not password_valid(password, row[4]):
            self.respond(401, {"error": "Логин или пароль некорректен"})
            return
        self.start_session(*row[:4])

    # СОЗДАНИЕ СЕССИИ И ТОКЕНА
    # secrets создаёт криптографически случайный токен с 32 байтами случайных данных.
    # Сам токен получает браузер, в таблице sessions хранится только SHA-256-хеш.
    # При утечке одной таблицы sessions нельзя просто взять хеш и использовать его как cookie.
    # У записи есть user_id и expires_at, срок действия установлен на 7 дней.
    # Это обычная серверная сессия, не JWT.
    # Новый вход создаёт новый токен; старые сессии при этом автоматически не отзываются.
    def start_session(self, user_id, login, firstname, is_admin):
        # При каждом входе создаём новый случайный токен. Сессия действует 7 дней.
        token = secrets.token_urlsafe(32)
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES (%s,%s,%s)",
                            (sha256(token.encode()).hexdigest(), user_id, datetime.now(timezone.utc) + timedelta(days=7)))
        self.respond(200, {"user": {"login": login, "firstname": decrypt(firstname), "is_admin": is_admin}},
                     self.cookie_value(token, 604800))

    # ВЫХОД ИЗ АККАУНТА
    # Удаляем запись сессии по хешу токена, затем отправляем пустую cookie с Max-Age=0.
    # Поэтому недостаточно просто скрыть личный кабинет: сервер тоже прекращает принимать эту сессию.
    # Остальные сессии пользователя на других устройствах этот выход не удаляет.
    def logout(self):
        jar = SimpleCookie()
        jar.load(self.headers.get("Cookie", ""))
        if COOKIE_NAME in jar:
            with db() as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM sessions WHERE token_hash=%s", (sha256(jar[COOKIE_NAME].value.encode()).hexdigest(),))
        self.respond(200, {"ok": True}, self.cookie_value("", 0))

    # СОЗДАНИЕ ЗАЯВКИ
    # Без действующей сессии возвращаем 401 и ничего не сохраняем.
    # Владельца заявки определяем по сессии: прислать чужой user_id вместо своего нельзя.
    # Проверяем услугу по списку, длину адреса, формат телефона и дату не раньше сегодняшней.
    # Адрес и телефон шифруем, а значения в SQL передаём параметрами.
    # Статус новой заявки задаётся сервером как «Новая».
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
                    VALUES (%s,%s,%s,%s,%s) RETURNING id""",
                    (user[0], service, encrypt(address), visit_date, encrypt(phone)))
                order_id = cur.fetchone()[0]
        self.respond(201, {"id": order_id, "status": "Новая"})

    # ПРАВА АДМИНИСТРАТОРА
    # Сначала проверяем сессию и is_admin, полученный из базы.
    # Если обычный пользователь вручную отправит запрос на этот маршрут, сервер вернёт 403.
    # Скрытие кнопки в интерфейсе только для удобства, настоящая проверка находится здесь.
    # Разрешены только четыре статуса из STATUSES, ID заявки должен быть положительным.
    # Обновление выполняется параметрическим запросом, для отсутствующей заявки возвращаем 404.
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


# Страницы по HTTP перенаправляем на HTTPS. POST по HTTP не принимаем.
class RedirectHandler(BaseHTTPRequestHandler):
    # ПЕРЕХОД С HTTP НА HTTPS
    # При открытии обычного HTTP возвращаем 308 и адрес HTTPS на порту 8443.
    # Этот порт обслуживает сайт, а 5433 — PostgreSQL, его нельзя открыть как страницу.
    def do_GET(self):
        self.send_response(308)
        self.send_header("Location", f"https://127.0.0.1:{PORT}{self.path}")
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ЗАПРЕТ ОТПРАВКИ ФОРМ ПО HTTP
    # Не обрабатываем логин, пароль и другие данные форм по незашифрованному HTTP.
    # Пользователь должен открыть HTTPS-версию сайта.
    def do_POST(self):
        self.send_error(403, "Use HTTPS")


# HTTPS И ЛОКАЛЬНЫЙ СЕРТИФИКАТ
# TLS шифрует соединение между браузером и сервером, включая пароль при входе.
# Для учебного запуска создаём самоподписанный сертификат для localhost и 127.0.0.1.
# Поэтому браузер может предупредить, что не доверяет сертификату.
# Это не сертификат доверенного центра, для публичного домена его нужно заменить.
# Приватный ключ хранится во временной папке с правами только для владельца.
# После перезапуска сертификат создаётся заново. HTTPS не заменяет хеширование паролей в базе.
def local_tls_context():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = Path("/tmp/cleaning.crt")
    key_path = Path("/tmp/cleaning.key")
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    # Закрываем доступ к файлу приватного ключа для остальных пользователей.
    key_path.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    return context


if __name__ == "__main__":
    if not DATABASE_URL and not DB_HOST:
        raise SystemExit("Set DATABASE_URL or DB_HOST for PostgreSQL connection")
    if not FERNET:
        raise SystemExit("Set DATA_ENCRYPTION_KEY for personal data encryption")
    init_db()
    if HTTPS:
        if REDIRECT_PORT:
            redirect_server = ThreadingHTTPServer((HOST, REDIRECT_PORT), RedirectHandler)
            Thread(target=redirect_server.serve_forever, daemon=True).start()
        server = ThreadingHTTPServer((HOST, PORT), Handler)
        server.socket = local_tls_context().wrap_socket(server.socket, server_side=True)
    else:
        server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Open {'https' if HTTPS else 'http'}://{HOST}:{PORT}")
    server.serve_forever()
