import hashlib
import json
import os
import secrets
import smtplib
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from email.message import EmailMessage
from urllib.parse import urlencode, urlparse

import jwt
import psycopg
import pyseto
from flask import Flask, jsonify, make_response, redirect, render_template, request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from psycopg.rows import dict_row
from pyseto import Key
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash


load_dotenv()
app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://auth_user:auth_demo_password@127.0.0.1:5433/auth_practice",
)
APP_SECRET = os.getenv("APP_SECRET", "development-app-secret-change-me")
JWT_SECRET = os.getenv("JWT_SECRET", "development-jwt-secret-change-me")
PASETO_SECRET = os.getenv("PASETO_SECRET", "development-paseto-secret-change-me")
HTTPS = os.getenv("HTTPS", "0") == "1"
COOKIE_OPTIONS = {
    "httponly": True,
    "secure": HTTPS,
    "samesite": "Lax",
    "path": "/",
}


def connection():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def init_db():
    schema = """
    CREATE TABLE IF NOT EXISTS auth_users (
        id BIGSERIAL PRIMARY KEY,
        login VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS auth_server_sessions (
        token_hash CHAR(64) PRIMARY KEY,
        user_id BIGINT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
        expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS auth_magic_links (
        token_hash CHAR(64) PRIMARY KEY,
        user_id BIGINT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
        expires_at TIMESTAMPTZ NOT NULL,
        used_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS auth_refresh_tokens (
        jti VARCHAR(64) PRIMARY KEY,
        user_id BIGINT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
        expires_at TIMESTAMPTZ NOT NULL,
        used_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS auth_oauth_codes (
        code_hash CHAR(64) PRIMARY KEY,
        user_id BIGINT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
        client_id VARCHAR(100) NOT NULL,
        redirect_uri TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        used_at TIMESTAMPTZ
    );
    """
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(schema)
            cur.execute(
                """
                INSERT INTO auth_users (login, email, password_hash)
                VALUES (%s, %s, %s)
                ON CONFLICT (login) DO NOTHING
                """,
                ("demo", "demo@example.ru", generate_password_hash("Demo12345")),
            )
        conn.commit()


def wait_for_db(attempts=30):
    for attempt in range(attempts):
        try:
            init_db()
            return
        except psycopg.OperationalError:
            if attempt == attempts - 1:
                raise
            time.sleep(1)


def sha256(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def utcnow():
    return datetime.now(timezone.utc)


def find_user(login=None, email=None, user_id=None):
    field, value = ("login", login) if login else ("email", email) if email else ("id", user_id)
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT id, login, email, password_hash FROM auth_users WHERE {field} = %s", (value,))
            return cur.fetchone()


def valid_credentials(login, password):
    user = find_user(login=login)
    if not user or not check_password_hash(user["password_hash"], password):
        return None
    return user


def body():
    return request.get_json(silent=True) or request.form.to_dict()


def public_user(user):
    return {"id": user["id"], "login": user["login"], "email": user["email"]}


def serializer(salt):
    return URLSafeTimedSerializer(APP_SECRET, salt=salt)


def create_access_token(user):
    now = utcnow()
    payload = {
        "sub": str(user["id"]),
        "login": user["login"],
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=15),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def create_refresh_token(user):
    now = utcnow()
    jti = secrets.token_urlsafe(24)
    expires = now + timedelta(days=7)
    payload = {
        "sub": str(user["id"]),
        "type": "refresh",
        "jti": jti,
        "iat": now,
        "exp": expires,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO auth_refresh_tokens (jti, user_id, expires_at) VALUES (%s, %s, %s)",
                (jti, user["id"], expires),
            )
        conn.commit()
    return token


def decode_jwt(token, expected_type):
    payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    if payload.get("type") != expected_type:
        raise jwt.InvalidTokenError("Неверный тип токена")
    return payload


def bearer_token():
    value = request.headers.get("Authorization", "")
    if not value.startswith("Bearer "):
        return None
    return value[7:]


def require_access(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        token = bearer_token()
        if not token:
            return jsonify(error="Нужен заголовок Authorization: Bearer <token>"), 401
        try:
            payload = decode_jwt(token, "access")
        except jwt.PyJWTError as exc:
            return jsonify(error=str(exc)), 401
        return view(payload, *args, **kwargs)

    return wrapped


def paseto_key():
    raw = hashlib.sha256(PASETO_SECRET.encode("utf-8")).digest()
    return Key.new(version=4, purpose="local", key=raw)


def create_paseto(user):
    payload = {
        "sub": str(user["id"]),
        "login": user["login"],
    }
    return pyseto.encode(paseto_key(), payload, exp=900).decode("utf-8")


def decode_paseto(token):
    decoded = pyseto.decode(paseto_key(), token, deserializer=json)
    return decoded.payload


def secure_response(payload, status=200):
    response = make_response(jsonify(payload), status)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'"
    return response


@app.after_request
def common_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'")
    return response


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/health")
def health():
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 AS ok")
            result = cur.fetchone()
    return jsonify(status="ok", database=result["ok"] == 1)


@app.post("/register")
def register():
    data = body()
    login = data.get("login", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    if len(login) < 3 or "@" not in email or len(password) < 8:
        return secure_response({"error": "Логин от 3 символов, корректная почта, пароль от 8 символов"}, 400)
    try:
        with connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO auth_users (login, email, password_hash) VALUES (%s, %s, %s) RETURNING id, login, email",
                    (login, email, generate_password_hash(password)),
                )
                user = cur.fetchone()
            conn.commit()
    except psycopg.errors.UniqueViolation:
        return secure_response({"error": "Логин или электронная почта уже используются"}, 409)
    return secure_response({"message": "Пользователь зарегистрирован", "user": public_user(user)}, 201)


@app.post("/auth/cookie/login")
def cookie_login():
    data = body()
    user = valid_credentials(data.get("login", ""), data.get("password", ""))
    if not user:
        return secure_response({"error": "Неверный логин или пароль"}, 401)
    token = serializer("cookie-auth").dumps({"user_id": user["id"]})
    response = secure_response({"message": "Вход через подписанную cookie выполнен", "user": public_user(user)})
    response.set_cookie("auth_cookie", token, max_age=3600, **COOKIE_OPTIONS)
    return response


@app.get("/auth/cookie/profile")
def cookie_profile():
    token = request.cookies.get("auth_cookie")
    try:
        payload = serializer("cookie-auth").loads(token, max_age=3600)
        user = find_user(user_id=payload["user_id"])
    except (BadSignature, SignatureExpired, TypeError):
        return secure_response({"error": "Cookie отсутствует или недействительна"}, 401)
    return secure_response({"method": "signed cookie", "user": public_user(user)})


@app.post("/auth/session/login")
def session_login():
    data = body()
    user = valid_credentials(data.get("login", ""), data.get("password", ""))
    if not user:
        return secure_response({"error": "Неверный логин или пароль"}, 401)
    raw_token = secrets.token_urlsafe(32)
    expires = utcnow() + timedelta(hours=8)
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO auth_server_sessions (token_hash, user_id, expires_at) VALUES (%s, %s, %s)",
                (sha256(raw_token), user["id"], expires),
            )
        conn.commit()
    response = secure_response({"message": "Серверная сессия создана", "user": public_user(user)})
    response.set_cookie("session_id", raw_token, max_age=28800, **COOKIE_OPTIONS)
    return response


@app.get("/auth/session/profile")
def session_profile():
    raw_token = request.cookies.get("session_id", "")
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT u.id, u.login, u.email
                FROM auth_server_sessions s JOIN auth_users u ON u.id = s.user_id
                WHERE s.token_hash = %s AND s.expires_at > NOW()
                """,
                (sha256(raw_token),),
            )
            user = cur.fetchone()
    if not user:
        return secure_response({"error": "Сессия отсутствует или истекла"}, 401)
    return secure_response({"method": "server session", "user": public_user(user)})


@app.post("/auth/passwordless/request")
def passwordless_request():
    data = body()
    user = find_user(email=data.get("email", "").strip().lower())
    message = "Если адрес зарегистрирован, ссылка для входа создана"
    if not user:
        return secure_response({"message": message})
    raw_token = secrets.token_urlsafe(32)
    expires = utcnow() + timedelta(minutes=10)
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO auth_magic_links (token_hash, user_id, expires_at) VALUES (%s, %s, %s)",
                (sha256(raw_token), user["id"], expires),
            )
        conn.commit()
    link = request.url_root.rstrip("/") + "/auth/passwordless/verify?" + urlencode({"token": raw_token})
    smtp_host = os.getenv("SMTP_HOST", "")
    if smtp_host:
        letter = EmailMessage()
        letter["From"] = os.getenv("SMTP_FROM", "auth-practice@example.ru")
        letter["To"] = user["email"]
        letter["Subject"] = "Ссылка для входа"
        letter.set_content("Ссылка для входа действует 10 минут:\n" + link)
        with smtplib.SMTP(smtp_host, int(os.getenv("SMTP_PORT", "587"))) as smtp:
            smtp.starttls()
            smtp.login(os.getenv("SMTP_USER", ""), os.getenv("SMTP_PASSWORD", ""))
            smtp.send_message(letter)
        return secure_response({"message": message})
    return secure_response({"message": message, "demo_magic_link": link})


@app.get("/auth/passwordless/verify")
def passwordless_verify():
    token_hash = sha256(request.args.get("token", ""))
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE auth_magic_links
                SET used_at = NOW()
                WHERE token_hash = %s AND used_at IS NULL AND expires_at > NOW()
                RETURNING user_id
                """,
                (token_hash,),
            )
            record = cur.fetchone()
        conn.commit()
    if not record:
        return secure_response({"error": "Ссылка недействительна, использована или истекла"}, 401)
    user = find_user(user_id=record["user_id"])
    return secure_response({"message": "Беспарольный вход выполнен", "user": public_user(user)})


@app.post("/auth/jwt/login")
def jwt_login():
    data = body()
    user = valid_credentials(data.get("login", ""), data.get("password", ""))
    if not user:
        return secure_response({"error": "Неверный логин или пароль"}, 401)
    return secure_response(
        {
            "access_token": create_access_token(user),
            "refresh_token": create_refresh_token(user),
            "token_type": "Bearer",
        }
    )


@app.get("/auth/jwt/profile")
@require_access
def jwt_profile(payload):
    user = find_user(user_id=int(payload["sub"]))
    return secure_response({"method": "JWT access", "user": public_user(user)})


@app.post("/auth/jwt/refresh")
def jwt_refresh():
    token = body().get("refresh_token", "")
    try:
        payload = decode_jwt(token, "refresh")
    except jwt.PyJWTError as exc:
        return secure_response({"error": str(exc)}, 401)
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE auth_refresh_tokens
                SET used_at = NOW()
                WHERE jti = %s AND user_id = %s AND used_at IS NULL AND expires_at > NOW()
                RETURNING user_id
                """,
                (payload["jti"], int(payload["sub"])),
            )
            record = cur.fetchone()
        conn.commit()
    if not record:
        return secure_response({"error": "Refresh-токен уже использован или отозван"}, 401)
    user = find_user(user_id=record["user_id"])
    return secure_response(
        {
            "access_token": create_access_token(user),
            "refresh_token": create_refresh_token(user),
            "token_type": "Bearer",
        }
    )


@app.get("/oauth/start")
def oauth_start():
    state = secrets.token_urlsafe(24)
    callback = request.url_root.rstrip("/") + "/oauth/callback"
    query = urlencode(
        {
            "client_id": "auth-practice-client",
            "redirect_uri": callback,
            "state": state,
        }
    )
    response = make_response(redirect("/oauth/provider/authorize?" + query))
    response.set_cookie("oauth_state", state, max_age=300, **COOKIE_OPTIONS)
    return response


@app.get("/oauth/provider/authorize")
def oauth_provider_authorize():
    client_id = request.args.get("client_id", "")
    redirect_uri = request.args.get("redirect_uri", "")
    state = request.args.get("state", "")
    parsed = urlparse(redirect_uri)
    expected = request.url_root.rstrip("/") + "/oauth/callback"
    if client_id != "auth-practice-client" or redirect_uri != expected or parsed.path != "/oauth/callback":
        return secure_response({"error": "Недопустимый OAuth-клиент"}, 400)
    return render_template(
        "oauth_login.html",
        client_id=client_id,
        redirect_uri=redirect_uri,
        state=state,
    )


@app.post("/oauth/provider/authorize")
def oauth_provider_login():
    client_id = request.form.get("client_id", "")
    redirect_uri = request.form.get("redirect_uri", "")
    state = request.form.get("state", "")
    parsed = urlparse(redirect_uri)
    expected = request.url_root.rstrip("/") + "/oauth/callback"
    if client_id != "auth-practice-client" or redirect_uri != expected or parsed.path != "/oauth/callback":
        return secure_response({"error": "Недопустимый OAuth-клиент"}, 400)
    user = valid_credentials(request.form.get("login", ""), request.form.get("password", ""))
    if not user:
        return secure_response({"error": "Неверный логин или пароль"}, 401)
    raw_code = secrets.token_urlsafe(32)
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO auth_oauth_codes (code_hash, user_id, client_id, redirect_uri, expires_at)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (sha256(raw_code), user["id"], client_id, redirect_uri, utcnow() + timedelta(minutes=2)),
            )
        conn.commit()
    return redirect(redirect_uri + "?" + urlencode({"code": raw_code, "state": state}))


@app.get("/oauth/callback")
def oauth_callback():
    state = request.args.get("state", "")
    if not state or not secrets.compare_digest(state, request.cookies.get("oauth_state", "")):
        return secure_response({"error": "OAuth state не совпадает"}, 401)
    code_hash = sha256(request.args.get("code", ""))
    callback = request.url_root.rstrip("/") + "/oauth/callback"
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE auth_oauth_codes
                SET used_at = NOW()
                WHERE code_hash = %s AND client_id = %s AND redirect_uri = %s
                  AND used_at IS NULL AND expires_at > NOW()
                RETURNING user_id
                """,
                (code_hash, "auth-practice-client", callback),
            )
            record = cur.fetchone()
        conn.commit()
    if not record:
        return secure_response({"error": "OAuth-код недействителен или использован"}, 401)
    user = find_user(user_id=record["user_id"])
    response = secure_response({"message": "OAuth2-вход через учебную единую точку выполнен", "user": public_user(user)})
    response.delete_cookie("oauth_state", path="/")
    return response


@app.post("/auth/paseto/login")
def paseto_login():
    data = body()
    user = valid_credentials(data.get("login", ""), data.get("password", ""))
    if not user:
        return secure_response({"error": "Неверный логин или пароль"}, 401)
    return secure_response({"paseto": create_paseto(user), "token_type": "Bearer"})


@app.get("/auth/paseto/profile")
def paseto_profile():
    token = bearer_token()
    if not token:
        return secure_response({"error": "Нужен заголовок Authorization: Bearer <token>"}, 401)
    try:
        payload = decode_paseto(token)
    except Exception as exc:
        return secure_response({"error": str(exc)}, 401)
    user = find_user(user_id=int(payload["sub"]))
    return secure_response({"method": "PASETO v4.local", "user": public_user(user)})


if __name__ == "__main__":
    wait_for_db()
    app.run(host="127.0.0.1", port=8001, debug=False)
