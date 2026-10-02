import os
import secrets
import sys
import requests

sys.stdout.reconfigure(encoding="utf-8")


BASE = os.getenv("BASE_URL", "http://127.0.0.1:8001")


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print("OK", message)


def main():
    session = requests.Session()
    suffix = secrets.token_hex(4)
    login = "student_" + suffix
    email = login + "@example.ru"
    password = "Student123"

    response = session.get(BASE + "/health")
    check(response.status_code == 200 and response.json()["database"], "PostgreSQL доступен")

    response = session.post(BASE + "/register", json={"login": login, "email": email, "password": password})
    check(response.status_code == 201, "регистрация")

    response = session.post(BASE + "/auth/cookie/login", json={"login": login, "password": password})
    check(response.status_code == 200 and "auth_cookie" in session.cookies, "вход через cookie")
    check(session.get(BASE + "/auth/cookie/profile").status_code == 200, "профиль через cookie")

    response = session.post(BASE + "/auth/session/login", json={"login": login, "password": password})
    check(response.status_code == 200 and "session_id" in session.cookies, "серверная сессия")
    check(session.get(BASE + "/auth/session/profile").status_code == 200, "профиль через серверную сессию")

    response = session.post(BASE + "/auth/passwordless/request", json={"email": email})
    magic_link = response.json()["demo_magic_link"]
    check(session.get(magic_link).status_code == 200, "одноразовая ссылка")
    check(session.get(magic_link).status_code == 401, "повтор одноразовой ссылки запрещён")

    response = session.post(BASE + "/auth/jwt/login", json={"login": login, "password": password})
    tokens = response.json()
    headers = {"Authorization": "Bearer " + tokens["access_token"]}
    check(session.get(BASE + "/auth/jwt/profile", headers=headers).status_code == 200, "JWT access")
    check(session.get(BASE + "/auth/jwt/profile", headers=headers).status_code == 200, "JWT access многоразовый")

    response = session.post(BASE + "/auth/jwt/refresh", json={"refresh_token": tokens["refresh_token"]})
    check(response.status_code == 200, "JWT refresh")
    response = session.post(BASE + "/auth/jwt/refresh", json={"refresh_token": tokens["refresh_token"]})
    check(response.status_code == 401, "повтор JWT refresh запрещён")

    response = session.get(BASE + "/oauth/start", allow_redirects=True)
    check(response.status_code == 200 and "Учебная единая точка входа" in response.text, "OAuth2 страница входа")
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(response.text, "html.parser")
    oauth_form = soup.select_one('form[action="/oauth/provider/authorize"]')
    oauth_data = {field["name"]: field.get("value", "") for field in oauth_form.select('input[type="hidden"]')}
    oauth_data.update({"login": login, "password": password})
    response = session.post(BASE + "/oauth/provider/authorize", data=oauth_data, allow_redirects=True)
    check(response.status_code == 200 and "OAuth2-вход" in response.json()["message"], "OAuth2 Authorization Code")

    response = session.post(BASE + "/auth/paseto/login", json={"login": login, "password": password})
    paseto = response.json()["paseto"]
    headers = {"Authorization": "Bearer " + paseto}
    check(session.get(BASE + "/auth/paseto/profile", headers=headers).status_code == 200, "PASETO v4.local")

    print("Все проверки выполнены успешно")


if __name__ == "__main__":
    main()
